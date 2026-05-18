defmodule QMI.QrtrDriver do
  @moduledoc """
  Request/response driver for QMI over QRTR. Sits on top of
  `QMI.Transport.QRTR` and adds the transaction-ID bookkeeping +
  caller bookkeeping the higher-level QMI service modules expect.

  This is the QRTR counterpart of `QMI.Driver`. It is deliberately a
  separate module rather than a branch inside `QMI.Driver` because the
  two paths have different lifecycles:

    * `QMI.Driver` / `QMI.DevBridge` opens one chardev and writes
      QMUX-framed bytes; QMUX carries the QMI service/client info
      inline.
    * `QMI.QrtrDriver` / `QMI.Transport.QRTR` owns one AF_QIPCRTR
      socket and addresses each request to the QRTR `(node, port)`
      pair the kernel published for that QMI service; the QMUX
      service/client fields don't exist on the wire — the address is
      the routing.

  The two will eventually share a common behaviour, but until the
  cdc-wdm path is lifted into `QMI.Transport.QMUX` (Step 3 in
  `QRTR_TRANSPORT.md`) keeping them separate avoids churn on the
  USB-modem deployments.

  ## Usage

      {:ok, drv} = QMI.QrtrDriver.start_link([])

      # DMS service id = 2, Get Manufacturer = msg id 0x0021.
      {:ok, response} = QMI.QrtrDriver.call(drv, 2, 0x0021, <<>>)
      response.tlvs
      # => %{1 => "QUALCOMM INCORPORATED", 2 => <<0, 0, 0, 0>>}
  """
  use GenServer
  require Logger

  alias QMI.Transport.QRTR

  ## ---- public API ------------------------------------------------

  @typedoc """
  Decoded QMI service response.

    * `:flags` — control flags from the message header (typically 2
      for a successful response, 4 for an indication).
    * `:txn` — transaction ID echoed back by the modem.
    * `:msg_id` — the QMI message ID this is responding to.
    * `:tlvs` — `%{tlv_type => value_binary}` map of every TLV the
      modem returned. Parsing the value is up to the caller (the
      shape depends on `msg_id`).
  """
  @type response :: %{
          flags: byte(),
          txn: non_neg_integer(),
          msg_id: non_neg_integer(),
          tlvs: %{byte() => binary()}
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: opts[:name])

  @doc """
  Send a QMI request and wait for the matching response.

  `payload` is the TLV bytes that follow the QMI message header (most
  small requests pass `<<>>`).

  Returns `{:ok, response}` on a matching reply, `{:error, :timeout}`
  if no reply arrives within `:timeout` ms (default 5_000), or
  `{:error, {:service_not_found, service_id}}` if QRTR never announced
  that service.
  """
  @spec call(GenServer.server(), non_neg_integer(), non_neg_integer(), binary(), keyword()) ::
          {:ok, response} | {:error, term()}
  def call(drv, service_id, msg_id, payload \\ <<>>, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5_000)
    GenServer.call(drv, {:call, service_id, msg_id, payload, timeout}, timeout * 2)
  end

  @doc "Returns the QRTR service routing table."
  def services(drv), do: GenServer.call(drv, :services)

  ## ---- GenServer state -------------------------------------------

  defmodule State do
    @moduledoc false

    defstruct transport: nil,
              # %{ {service_id, txn} => {from, timer_ref} }
              pending: %{},
              # last txn issued per service, 1..0xFFFF wrap
              next_txn: %{}
  end

  @impl GenServer
  def init(opts) do
    {:ok, transport} = QRTR.start_link(Keyword.put(opts, :owner, self()))
    {:ok, %State{transport: transport}}
  end

  ## ---- handle_call ----------------------------------------------

  @impl GenServer
  def handle_call(:services, _from, state) do
    {:reply, QRTR.services(state.transport), state}
  end

  def handle_call({:call, service_id, msg_id, payload, timeout}, from, state) do
    {txn, state} = next_txn(state, service_id)

    # QMI service message header: flags(1), txn(2 LE), msg_id(2 LE),
    # msg_len(2 LE), then the TLV bytes. (CTL service uses an 8-bit
    # txn; we don't support CTL here because QRTR has no CTL.)
    msg =
      <<0, txn::16-little, msg_id::16-little, byte_size(payload)::16-little, payload::binary>>

    case QRTR.send(state.transport, service_id, 0, msg) do
      :ok ->
        timer = Process.send_after(self(), {:timeout, service_id, txn}, timeout)

        state = %{
          state
          | pending: Map.put(state.pending, {service_id, txn}, {from, timer})
        }

        {:noreply, state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  ## ---- handle_info ----------------------------------------------

  @impl GenServer
  def handle_info(
        {:qmi_in, transport, service_id,
         <<flags, txn::16-little, msg_id::16-little, msg_len::16-little,
           tlv_bytes::binary-size(msg_len)>>},
        %{transport: transport} = state
      ) do
    key = {service_id, txn}

    case Map.pop(state.pending, key) do
      {nil, _} ->
        # Could be an indication (flags == 4) or a late/duplicate reply.
        Logger.debug(
          "[QMI.QrtrDriver] unsolicited service=#{service_id} msg_id=0x#{Integer.to_string(msg_id, 16)} flags=#{flags}"
        )

        {:noreply, state}

      {{from, timer}, rest} ->
        Process.cancel_timer(timer)

        reply = %{
          flags: flags,
          txn: txn,
          msg_id: msg_id,
          tlvs: decode_tlvs(tlv_bytes)
        }

        GenServer.reply(from, {:ok, reply})
        {:noreply, %{state | pending: rest}}
    end
  end

  def handle_info({:qmi_in, _, _, _}, state) do
    # Stray message from a previous transport instance — ignore.
    {:noreply, state}
  end

  def handle_info({:timeout, service_id, txn}, state) do
    case Map.pop(state.pending, {service_id, txn}) do
      {nil, _} ->
        {:noreply, state}

      {{from, _timer}, rest} ->
        GenServer.reply(from, {:error, :timeout})
        {:noreply, %{state | pending: rest}}
    end
  end

  ## ---- internals ------------------------------------------------

  defp next_txn(state, service_id) do
    cur = Map.get(state.next_txn, service_id, 0)
    next = if cur >= 0xFFFF, do: 1, else: cur + 1
    {next, %{state | next_txn: Map.put(state.next_txn, service_id, next)}}
  end

  # TLVs are `type(1) + length(2 LE) + value(length)`, packed back to
  # back until the buffer is exhausted.
  defp decode_tlvs(bytes), do: decode_tlvs(bytes, %{})

  defp decode_tlvs(<<>>, acc), do: acc

  defp decode_tlvs(<<type, len::16-little, value::binary-size(len), rest::binary>>, acc) do
    decode_tlvs(rest, Map.put(acc, type, value))
  end

  defp decode_tlvs(_partial, acc), do: acc
end

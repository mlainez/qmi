# SPDX-FileCopyrightText: 2020 Jon Carstens
# SPDX-FileCopyrightText: 2021 Frank Hunleth
# SPDX-FileCopyrightText: 2021 Matt Ludwigs
# SPDX-FileCopyrightText: 2023 Liv Cella
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.Driver do
  @moduledoc false

  use GenServer

  require Logger

  defmodule State do
    @moduledoc false

    defstruct transport_mod: nil,
              transport: nil,
              transport_opts: [],
              retry_min_ms: nil,
              retry_ms: nil,
              device_path: nil,
              transactions: %{},
              last_ctl_transaction: 0,
              last_service_transaction: 256,
              indication_callback: nil
  end

  @request_type 0

  # Backoff used when the transport fails to start or exits (e.g. the
  # QRTR socket family isn't available yet, or the modem restarted).
  @transport_retry_min_ms 1_000
  @transport_retry_max_ms 30_000

  @type options() :: [
          name: module(),
          device_path: Path.t(),
          transport_mod: module(),
          transport_opts: keyword(),
          transport_retry_ms: pos_integer(),
          indication_callback: QMI.indication_callback_fun()
        ]

  @spec start_link(options) :: GenServer.on_start()
  def start_link(init_args) do
    qmi = Keyword.fetch!(init_args, :name)

    GenServer.start_link(__MODULE__, init_args, name: name(qmi))
  end

  defp name(qmi) do
    Module.concat(qmi, Driver)
  end

  @doc """
  Send a message and return the response
  """
  @spec call(GenServer.server(), non_neg_integer(), QMI.request(), keyword()) :: any()
  def call(qmi, client_id, request, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5_000)

    GenServer.call(name(qmi), {:call, client_id, request, timeout}, timeout * 2)
  end

  @impl GenServer
  def init(opts) do
    # The transport is linked to us. Trap exits so a transport that
    # fails to open (or dies later) is restarted with backoff instead
    # of taking the driver down and crash-looping QMI.Supervisor.
    Process.flag(:trap_exit, true)

    transport_mod = Keyword.get(opts, :transport_mod, QMI.Transport.QMUX)

    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.put(:owner, self())
      # The QMUX transport needs the device_path; the QRTR transport
      # ignores it. Passing it through is harmless either way.
      |> Keyword.put_new(:device_path, opts[:device_path])

    state = %State{
      transport_mod: transport_mod,
      transport_opts: transport_opts,
      retry_min_ms: Keyword.get(opts, :transport_retry_ms, @transport_retry_min_ms),
      retry_ms: Keyword.get(opts, :transport_retry_ms, @transport_retry_min_ms),
      device_path: opts[:device_path],
      indication_callback: opts[:indication_callback]
    }

    {:ok, state, {:continue, :start_transport}}
  end

  @impl GenServer
  def handle_continue(:start_transport, state) do
    {:noreply, start_transport(state)}
  end

  @impl GenServer
  def handle_call({:call, _client_id, _request, _timeout}, _from, %{transport: nil} = state) do
    {:reply, {:error, :transport_unavailable}, state}
  end

  def handle_call({:call, client_id, request, timeout}, from, state) do
    case do_request(request, client_id, state) do
      {:ok, transaction, state} ->
        timer = Process.send_after(self(), {:timeout, transaction}, timeout)

        {:noreply,
         %{
           state
           | transactions: Map.put(state.transactions, transaction, {from, request, timer})
         }}

      {:error, reason, state} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_info({:timeout, transaction_id}, state) do
    {:noreply, fail_transaction_id(state, transaction_id, :timeout)}
  end

  def handle_info(:start_transport, %{transport: nil} = state) do
    {:noreply, start_transport(state)}
  end

  def handle_info(:start_transport, state), do: {:noreply, state}

  def handle_info({:EXIT, transport, reason}, %{transport: transport} = state) do
    Logger.warning("[QMI.Driver] transport exited: #{inspect(reason)}")

    state =
      Enum.reduce(Map.keys(state.transactions), %{state | transport: nil}, fn id, acc ->
        fail_transaction_id(acc, id, :transport_down)
      end)

    {:noreply, schedule_transport_restart(state)}
  end

  def handle_info({:EXIT, _pid, _reason}, state), do: {:noreply, state}

  def handle_info({:qmi_in, transport, service_id, client_id, qmi_msg}, %{transport: transport} = state) do
    # Traffic from the modem means the transport is healthy again.
    state = %{state | retry_ms: state.retry_min_ms}

    case QMI.Message.parse(service_id, client_id, qmi_msg) do
      {:ok, message} ->
        handle_report(message, state)

      {:error, _reason} ->
        Logger.warning(
          "[QMI.Driver] invalid message from service #{service_id}: #{inspect(qmi_msg)}"
        )

        {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp start_transport(state) do
    case state.transport_mod.start_link(state.transport_opts) do
      {:ok, transport} ->
        %{state | transport: transport}

      {:error, reason} ->
        Logger.warning("[QMI.Driver] transport failed to start: #{inspect(reason)}")
        schedule_transport_restart(state)
    end
  end

  defp schedule_transport_restart(state) do
    Logger.info("[QMI.Driver] restarting transport in #{state.retry_ms} ms")
    _ = Process.send_after(self(), :start_transport, state.retry_ms)
    %{state | retry_ms: min(state.retry_ms * 2, @transport_retry_max_ms)}
  end

  defp do_request(request, client_id, state) do
    {transaction, state} = next_transaction(request.service_id, state)

    # QMI service-message wire format (the same on both transports;
    # transport adds whatever outer framing/routing its wire needs):
    #   <<type(1), txn(little-N), payload>>
    # type=0 means "request". Transaction is 1 byte for the CTL service
    # (service_id=0) and 2 bytes for every other service.
    tran_size = if request.service_id == 0, do: 8, else: 16

    qmi_msg =
      [<<@request_type, transaction::little-size(tran_size)>>, request.payload]
      |> IO.iodata_to_binary()

    case transport_send(state, request.service_id, client_id, qmi_msg) do
      :ok -> {:ok, transaction, state}
      {:error, reason} -> {:error, reason, state}
    end
  end

  # Transports return `{:error, reason}` for recoverable problems (e.g.
  # QRTR's `{:service_not_found, id}` before the modem announces a
  # service). Report those to the caller rather than crashing.
  defp transport_send(state, service_id, client_id, qmi_msg) do
    case state.transport_mod.send(state.transport, service_id, client_id, qmi_msg) do
      :ok -> :ok
      {:error, _reason} = error -> error
      other -> {:error, other}
    end
  catch
    :exit, _reason -> {:error, :transport_down}
  end

  defp next_transaction(0, %{last_ctl_transaction: tran} = state) do
    # Control service transaction can only be 1 byte, which
    # is a max value of 255. Ensure we don't go over here
    # otherwise it will fail silently
    tran = if tran < 255, do: tran + 1, else: 1

    {tran, %{state | last_ctl_transaction: tran}}
  end

  defp next_transaction(_service, %{last_service_transaction: tran} = state) do
    # Service requests have 2-byte transaction IDs.
    # Use IDs from 256 to 65536 to avoid any confusion with control requests.
    tran = if tran < 65_535, do: tran + 1, else: 256

    {tran, %{state | last_service_transaction: tran}}
  end

  defp run_callback_fun(_indication, %{indication_callback: nil}) do
    :ok
  end

  defp run_callback_fun(indication, %{indication_callback: callback_fun}) do
    callback_fun.(indication)
  end

  defp handle_report(%{type: :indication} = msg, state) do
    case QMI.Codec.Indication.parse(msg) do
      {:ok, indication} ->
        :ok = run_callback_fun(indication, state)

      {:error, _} ->
        Logger.warning("QMI: Unknown indication: #{inspect(msg, limit: :infinity)}")
    end

    {:noreply, state}
  end

  defp handle_report(%{transaction_id: transaction_id, code: :success} = msg, state) do
    {transaction, transactions} = Map.pop(state.transactions, transaction_id)

    case transaction do
      {from, request, timer} ->
        _ = Process.cancel_timer(timer)
        result = msg.message |> request.decode.()

        if match?({:error, _reason}, result) do
          Logger.warning(
            "QMI: Error decoding response to #{inspect(request)}: message was #{inspect(msg.message, limit: :infinity)}"
          )
        end

        GenServer.reply(from, result)

      nil ->
        Logger.warning(
          "QMI: Ignoring response for unknown transaction: #{inspect(transaction_id)}"
        )
    end

    {:noreply, %{state | transactions: transactions}}
  end

  defp handle_report(
         %{transaction_id: transaction_id, code: :failure, error: error, message: message} =
           msg,
         state
       ) do
    verbose_reason = parse_verbose_call_end_reason(message)

    Logger.warning(
      "[QMI.Driver] Request failed with error: #{inspect(error)}, " <>
        "service: #{inspect(msg[:service_id])}, " <>
        "verbose_reason: #{inspect(verbose_reason)}, " <>
        "raw message: #{inspect(message, limit: :infinity)}"
    )

    {:noreply, fail_transaction_id(state, transaction_id, error)}
  end

  defp handle_report(%{transaction_id: transaction_id, code: :failure, error: error}, state) do
    Logger.warning("[QMI.Driver] Request failed with error: #{inspect(error)}")
    {:noreply, fail_transaction_id(state, transaction_id, error)}
  end

  # Parse verbose call end reason TLVs from a failed WDS response body.
  # The message body starts with message_id (2 bytes) and message_size (2 bytes),
  # followed by TLVs. TLV 0x10 = call end reason, TLV 0x11 = verbose call end reason.
  defp parse_verbose_call_end_reason(
         <<_message_id::little-16, _message_size::little-16, tlvs::binary>>
       ) do
    parse_failure_tlvs(tlvs, %{})
  end

  defp parse_verbose_call_end_reason(_), do: %{}

  defp parse_failure_tlvs(<<>>, acc), do: acc

  # TLV 0x02 - Result Code (skip, already handled)
  defp parse_failure_tlvs(
         <<0x02, 0x04::little-16, _code::little-16, _error::little-16, rest::binary>>,
         acc
       ) do
    parse_failure_tlvs(rest, acc)
  end

  # TLV 0x10 - Call End Reason (simple)
  defp parse_failure_tlvs(
         <<0x10, 0x02::little-16, call_end_reason::little-16, rest::binary>>,
         acc
       ) do
    parse_failure_tlvs(rest, Map.put(acc, :call_end_reason, call_end_reason))
  end

  # TLV 0x11 - Verbose Call End Reason (type + reason)
  defp parse_failure_tlvs(
         <<0x11, 0x04::little-16, reason_type::little-16, reason::little-16, rest::binary>>,
         acc
       ) do
    acc =
      acc
      |> Map.put(:call_end_reason_type, parse_call_end_reason_type(reason_type))
      |> Map.put(:verbose_call_end_reason, reason)

    parse_failure_tlvs(rest, acc)
  end

  # Skip unknown TLVs
  defp parse_failure_tlvs(
         <<_type, length::little-16, _values::binary-size(length), rest::binary>>,
         acc
       ) do
    parse_failure_tlvs(rest, acc)
  end

  # Bail on unparseable remainder
  defp parse_failure_tlvs(_other, acc), do: acc

  defp parse_call_end_reason_type(0x00), do: :unspecified
  defp parse_call_end_reason_type(0x01), do: :mobile_ip
  defp parse_call_end_reason_type(0x02), do: :internal
  defp parse_call_end_reason_type(0x03), do: :call_manager_defined
  defp parse_call_end_reason_type(0x06), do: :three_gpp_specification_defined
  defp parse_call_end_reason_type(0x07), do: :ppp
  defp parse_call_end_reason_type(0x08), do: :ehrpd
  defp parse_call_end_reason_type(0x09), do: :ipv6
  defp parse_call_end_reason_type(0x0C), do: :handoff
  defp parse_call_end_reason_type(other), do: {:unknown, other}

  defp fail_transaction_id(state, transaction_id, error) do
    case Map.pop(state.transactions, transaction_id) do
      {{from, _request, timer}, transactions} ->
        _ = Process.cancel_timer(timer)
        GenServer.reply(from, {:error, error})
        %{state | transactions: transactions}

      {nil, _transactions} ->
        # e.g. a failure response arriving after the request timed out
        state
    end
  end
end

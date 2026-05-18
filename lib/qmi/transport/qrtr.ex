defmodule QMI.Transport.QRTR do
  @moduledoc """
  QMI-over-QRTR transport for Qualcomm SoCs with in-kernel modem
  firmware (msm8953, sdm632, sdm660, sm6125 …) that publish QMI
  services on the Qualcomm IPC Router instead of cdc-wdm-style
  chardevs.

  The transport opens an `AF_QIPCRTR` datagram socket via Erlang's
  `:socket`, listens for `QRTR_TYPE_NEW_SERVER` / `QRTR_TYPE_DEL_SERVER`
  control packets to build a routing table from QMI service ID →
  `(node, port)`, and `sendto`s each outbound message to the address
  matching its target service. Inbound packets are tagged with the
  service ID inferred from the source `(node, port)` and forwarded to
  the owner as `{:qmi_in, handle, service_id, payload}`.

  Wire-format note: QMI messages on QRTR are *unwrapped* — there is
  no outer QMUX header. The QMUX `service_id`/`client_id` fields are
  carried out-of-band by the socket address. Payload bytes start at
  the QMI control flags. The driver's encoding/decoding stays the
  same on both transports; only the framing differs and is owned by
  each transport.

  **Skeleton only — not functional yet.** This module exists so the
  C-free, pure-`:socket` QRTR implementation can be filled in
  incrementally in follow-up sessions without rebuilding the rest of
  the library. See `lib/qmi/transport.ex` for the contract.
  """
  @behaviour QMI.Transport

  use GenServer
  require Logger

  @af_qipcrtr 42

  # QRTR control packet types (linux/qrtr.h)
  @qrtr_type_data         1
  @qrtr_type_hello        2
  @qrtr_type_bye          3
  @qrtr_type_new_server   4
  @qrtr_type_del_server   5
  @qrtr_type_del_client   6
  @qrtr_type_resume_tx    7
  @qrtr_type_exit         8
  @qrtr_type_ping         9
  @qrtr_type_new_lookup   10
  @qrtr_type_del_lookup   11

  # Unused-warning suppression; these will be used as the body fills in.
  _ = [
    @qrtr_type_data, @qrtr_type_hello, @qrtr_type_bye,
    @qrtr_type_new_server, @qrtr_type_del_server, @qrtr_type_del_client,
    @qrtr_type_resume_tx, @qrtr_type_exit, @qrtr_type_ping,
    @qrtr_type_new_lookup, @qrtr_type_del_lookup
  ]

  defmodule State do
    @moduledoc false
    defstruct socket: nil,
              owner: nil,
              # %{service_id => {node, port}}
              services: %{}
  end

  @impl QMI.Transport
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: opts[:name])

  @impl QMI.Transport
  def send(_handle, _service_id, _client_id, _payload), do: {:error, :not_implemented}

  @impl QMI.Transport
  def close(handle), do: GenServer.stop(handle)

  ## GenServer

  @impl GenServer
  def init(opts) do
    owner = opts[:owner] || self()
    {:ok, %State{owner: owner}, {:continue, :open_socket}}
  end

  @impl GenServer
  def handle_continue(:open_socket, state) do
    case :socket.open(@af_qipcrtr, :dgram, 0) do
      {:ok, sock} ->
        Logger.info("[QMI.Transport.QRTR] AF_QIPCRTR socket opened")
        # TODO: send QRTR_TYPE_NEW_LOOKUP control packet so the kernel
        # streams the current service table + future advertise/withdraw
        # events to us.
        {:noreply, %{state | socket: sock}}

      {:error, reason} ->
        Logger.error("[QMI.Transport.QRTR] AF_QIPCRTR open failed: #{inspect(reason)}")
        {:stop, {:socket_open_failed, reason}, state}
    end
  end
end

defmodule QMI.Transport.QRTR do
  @moduledoc """
  QMI-over-QRTR transport for Qualcomm SoCs whose in-kernel modem
  firmware publishes QMI services on the Qualcomm IPC Router (e.g.
  msm8953 / sdm632 / sm6125 / sdm660 — Fairphone 3+ falls into this
  bucket) instead of presenting a `cdc-wdm`-style chardev.

  ## How it works

    * Opens an `AF_QIPCRTR` (family 42) datagram socket via OTP's
      `:socket`. The kernel auto-assigns a port the first time we
      send.
    * Sends a `NEW_LOOKUP` control packet to the local node's
      `QRTR_PORT_CTRL` (`0xfffffffe`) asking the kernel to stream the
      current service table and future advertise/withdraw events.
    * Parses incoming `NEW_SERVER` / `DEL_SERVER` packets and keeps a
      `service_id => {node, port}` map.
    * Outbound QMI messages from `QMI.Driver` are addressed to the
      `(node, port)` for the requested service and `sendto`'d. Note
      that on QRTR, QMI messages are carried *without* the QMUX
      outer header — the QMUX `service_id` / `client_id` are implicit
      in the socket address.
    * Inbound data packets (sender port != `CTRL`) are forwarded to
      the owner process as `{:qmi_in, transport_pid, service_id,
      payload}`. The service_id is inferred from the source address
      via the routing table.

  All wire I/O is pure Elixir on top of OTP `:socket`. No C port.

  ## Usage

      {:ok, t} = QMI.Transport.QRTR.start_link(owner: self())
      :timer.sleep(500)            # let service announcements arrive
      QMI.Transport.QRTR.services(t)
      # => %{1 => {0, 46}, 2 => {0, 54}, 3 => {0, 40}, ...}

      QMI.Transport.QRTR.lookup(t, 2)
      # => {:ok, {0, 54}}          # DMS lives at QRTR node 0, port 54
  """
  @behaviour QMI.Transport

  use GenServer
  require Logger

  ## ---- on-the-wire constants -------------------------------------

  @af_qipcrtr 42

  @qrtr_port_ctrl 0xFFFFFFFE

  # Subset of QRTR control-packet types from `linux/qrtr.h` we
  # actually parse on the receive path.
  @qrtr_type_new_server 4
  @qrtr_type_del_server 5
  @qrtr_type_new_lookup 10

  # The kernel-side sockaddr_qrtr is {sa_family_t family, __u32 node,
  # __u32 port}. OTP :socket emits the 2-byte family for us, then
  # appends our `:addr` bytes. The kernel reads `sq_node` at offset 4
  # (after a 2-byte pad), so we hand it pad(2) + node(4 LE) + port(4 LE).
  defp sockaddr(node, port) do
    %{family: @af_qipcrtr, addr: <<0::16, node::32-little, port::32-little>>}
  end

  defp parse_sockaddr(%{family: @af_qipcrtr, addr: <<_::16, node::32-little, port::32-little, _::binary>>}),
    do: {node, port}

  defp parse_sockaddr(_), do: :unknown

  ## ---- public API ------------------------------------------------

  @impl QMI.Transport
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: opts[:name])
  end

  @impl QMI.Transport
  def send(handle, service_id, _client_id, payload) do
    GenServer.call(handle, {:send, service_id, payload})
  end

  @impl QMI.Transport
  def close(handle), do: GenServer.stop(handle)

  @doc "Returns the current service routing table — `service_id => {node, port}`."
  @spec services(GenServer.server()) :: %{non_neg_integer() => {non_neg_integer(), non_neg_integer()}}
  def services(handle), do: GenServer.call(handle, :services)

  @doc "Look up the `(node, port)` for a QMI service ID."
  @spec lookup(GenServer.server(), non_neg_integer()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}} | :not_found
  def lookup(handle, service_id), do: GenServer.call(handle, {:lookup, service_id})

  ## ---- GenServer state -------------------------------------------

  defmodule State do
    @moduledoc false
    defstruct socket: nil,
              owner: nil,
              reader: nil,
              # %{service_id => {node, port}} — latest "winning" address
              services: %{},
              # for inbound demux: %{{node, port} => service_id}
              addrs: %{},
              local_node: 0
  end

  @impl GenServer
  def init(opts) do
    owner = opts[:owner] || self()
    Process.flag(:trap_exit, true)
    {:ok, %State{owner: owner}, {:continue, :open_socket}}
  end

  @impl GenServer
  def handle_continue(:open_socket, state) do
    with {:ok, sock} <- :socket.open(@af_qipcrtr, :dgram, 0),
         # Subscribe to all-services advertise/withdraw events. Sending
         # to (local_node, CTRL) — destination node is read from our
         # own sockname after the kernel auto-assigns a port.
         :ok <- :socket.sendto(sock, new_lookup_packet(), sockaddr(local_node(sock), @qrtr_port_ctrl)) do
      reader = start_reader(sock, self())
      Logger.info("[QMI.Transport.QRTR] subscribed to QRTR service announcements")
      {:noreply, %State{state | socket: sock, reader: reader, local_node: local_node(sock)}}
    else
      err ->
        Logger.error("[QMI.Transport.QRTR] open/subscribe failed: #{inspect(err)}")
        {:stop, {:qrtr_open_failed, err}, state}
    end
  end

  ## ---- handle_call ----------------------------------------------

  @impl GenServer
  def handle_call(:services, _from, state), do: {:reply, state.services, state}

  def handle_call({:lookup, service_id}, _from, state) do
    case Map.fetch(state.services, service_id) do
      {:ok, addr} -> {:reply, {:ok, addr}, state}
      :error -> {:reply, :not_found, state}
    end
  end

  def handle_call({:send, service_id, payload}, _from, state) do
    case Map.fetch(state.services, service_id) do
      {:ok, {node, port}} ->
        {:reply, :socket.sendto(state.socket, payload, sockaddr(node, port)), state}

      :error ->
        {:reply, {:error, {:service_not_found, service_id}}, state}
    end
  end

  ## ---- handle_info ----------------------------------------------

  @impl GenServer
  def handle_info({:qrtr_recv, from, data}, state) do
    {node, port} = parse_sockaddr(from)
    {:noreply, dispatch(node, port, data, state)}
  end

  def handle_info({:EXIT, reader, _reason}, %{reader: reader} = state) do
    # Reader died (socket closed, etc) — stop. Supervisor will restart.
    {:stop, :reader_exited, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl GenServer
  def terminate(_reason, %{socket: nil}), do: :ok
  def terminate(_reason, %{socket: sock}), do: :socket.close(sock)

  ## ---- internals ------------------------------------------------

  # CTRL packets carry control commands. Data packets carry QMI bytes
  # for whichever service `(node, port)` they came from.
  defp dispatch(_node, @qrtr_port_ctrl, data, state), do: handle_ctrl(data, state)

  defp dispatch(node, port, data, state) do
    case Map.fetch(state.addrs, {node, port}) do
      {:ok, service_id} ->
        Kernel.send(state.owner, {:qmi_in, self(), service_id, data})

      :error ->
        Logger.debug(
          "[QMI.Transport.QRTR] ignoring data from unknown peer #{node}:#{port}"
        )
    end

    state
  end

  defp handle_ctrl(
         <<@qrtr_type_new_server::32-little,
           service::32-little,
           _instance::32-little,
           node::32-little,
           port::32-little,
           _::binary>>,
         state
       ) do
    Logger.debug("[QMI.Transport.QRTR] +service #{service} @ #{node}:#{port}")

    %{
      state
      | services: Map.put(state.services, service, {node, port}),
        addrs: Map.put(state.addrs, {node, port}, service)
    }
  end

  defp handle_ctrl(
         <<@qrtr_type_del_server::32-little,
           service::32-little,
           _instance::32-little,
           node::32-little,
           port::32-little,
           _::binary>>,
         state
       ) do
    Logger.debug("[QMI.Transport.QRTR] -service #{service} @ #{node}:#{port}")

    %{
      state
      | services: Map.delete(state.services, service),
        addrs: Map.delete(state.addrs, {node, port})
    }
  end

  defp handle_ctrl(_other, state), do: state

  defp new_lookup_packet do
    # cmd + (service, instance, node, port) — all zeros = wildcard.
    <<@qrtr_type_new_lookup::32-little, 0::32-little, 0::32-little, 0::32-little, 0::32-little>>
  end

  defp local_node(sock) do
    case :socket.sockname(sock) do
      {:ok, %{addr: <<_::16, node::32-little, _port::32-little, _::binary>>}} -> node
      _ -> 0
    end
  end

  # ---- reader process ---------------------------------------------
  #
  # `:socket.recvfrom` blocks, so we keep it off the GenServer. The
  # reader is spawn_linked: if the socket closes, the reader exits
  # and the GenServer follows via the trapped EXIT.

  defp start_reader(sock, parent) do
    spawn_link(fn -> reader_loop(sock, parent) end)
  end

  defp reader_loop(sock, parent) do
    case :socket.recvfrom(sock, 4096, :infinity) do
      {:ok, {from, data}} ->
        Kernel.send(parent, {:qrtr_recv, from, data})
        reader_loop(sock, parent)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning("[QMI.Transport.QRTR] reader recv error: #{inspect(reason)}")
        :ok
    end
  end
end

defmodule QMI.Transport.QMUX do
  @moduledoc """
  QMUX-over-chardev transport — the path used by USB modems (cdc-wdm)
  and by in-kernel modems that present a `wwan*qmi*` chardev.

  Owns a `QMI.DevBridge` port, opens the configured device file, and
  on each `send/4`:

    * prepends the 3-byte QMUX per-service header
      `<<qmux_flags=0, service_id, client_id>>`,
    * wraps the whole thing in the outer QMUX header
      `<<0x01, len::little-16>>` (length includes itself), and
    * writes the result to the chardev.

  Inbound bytes from the chardev are unwrapped the same way: outer
  QMUX header is stripped, then the QMUX per-service header is split
  off, and the remaining QMI service message is forwarded to the
  transport owner as

      {:qmi_in, transport_pid, service_id, client_id, qmi_message}

  Same shape as `QMI.Transport.QRTR` emits.
  """
  @behaviour QMI.Transport

  use GenServer
  require Logger

  alias QMI.DevBridge

  defmodule State do
    @moduledoc false
    defstruct bridge: nil,
              ref: nil,
              owner: nil,
              device_path: nil
  end

  ## ---- public API (QMI.Transport behaviour) ----------------------

  @impl QMI.Transport
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: opts[:name])

  @impl QMI.Transport
  def send(handle, service_id, client_id, qmi_message) do
    GenServer.call(handle, {:send, service_id, client_id, qmi_message})
  end

  @impl QMI.Transport
  def close(handle), do: GenServer.stop(handle)

  ## ---- GenServer ------------------------------------------------

  @impl GenServer
  def init(opts) do
    owner = opts[:owner] || raise ArgumentError, "QMI.Transport.QMUX requires :owner"
    device_path = opts[:device_path] || raise ArgumentError, "QMI.Transport.QMUX requires :device_path"
    {:ok, %State{owner: owner, device_path: device_path}, {:continue, :open}}
  end

  @impl GenServer
  def handle_continue(:open, state) do
    {:ok, bridge} = DevBridge.start_link([])
    {:ok, ref} = DevBridge.open(bridge, state.device_path, [:read, :write])
    {:noreply, %{state | bridge: bridge, ref: ref}}
  end

  @impl GenServer
  def handle_call({:send, service_id, client_id, qmi_msg}, _from, state) do
    # QMUX per-service header (3 bytes) + the QMI service message.
    payload = [<<0, service_id, client_id>>, qmi_msg]
    # Outer QMUX header: type byte 0x01, then a 16-bit LE length that
    # includes the 2 length bytes themselves.
    len = IO.iodata_length(payload) + 2
    frame = [<<0x01, len::little-16>>, payload]
    {:ok, _} = DevBridge.write(state.bridge, frame)
    {:reply, :ok, state}
  end

  ## ---- DevBridge notifications ----------------------------------

  @impl GenServer
  def handle_info({:dev_bridge, ref, :read, data}, %{ref: ref} = state) do
    case unframe(data) do
      {:ok, service_id, client_id, qmi_msg} ->
        Kernel.send(state.owner, {:qmi_in, self(), service_id, client_id, qmi_msg})

      {:error, reason} ->
        Logger.warning(
          "[QMI.Transport.QMUX] #{state.device_path} bad frame (#{inspect(reason)}): #{inspect(data)}"
        )
    end

    {:noreply, state}
  end

  def handle_info({:dev_bridge, ref, :error, err}, %{ref: ref} = state) do
    Logger.error("[QMI.Transport.QMUX] #{state.device_path}: #{inspect(err)}")
    {:noreply, state}
  end

  def handle_info({:dev_bridge, ref, :closed}, %{ref: ref} = state) do
    # Reopen — same recovery behaviour the old inline path had.
    {:noreply, state, {:continue, :open}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  ## ---- internals ------------------------------------------------

  # <<0x01, len::little-16, qmux_flags::8, service::8, client::8, qmi_msg::binary>>
  defp unframe(<<0x01, _len::little-16, _qmux_flags::8, service::8, client::8, rest::binary>>),
    do: {:ok, service, client, rest}

  defp unframe(_), do: {:error, :bad_qmux_frame}
end

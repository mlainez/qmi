defmodule QMI.Transport.QMUX do
  @moduledoc """
  QMUX-over-chardev transport: the existing `cdc-wdm` / wwan-chardev
  path. This is a placeholder; the real implementation is currently
  inlined inside `QMI.Driver` + `QMI.DevBridge` and will be lifted in
  here when the Driver refactor lands.

  **Not yet wired up.** The Driver still uses `QMI.DevBridge` directly
  to avoid disrupting working USB-modem deployments. This module
  exists so the QRTR transport can be developed against the same
  behaviour and the lift can happen as a separate, mechanical step.
  """
  @behaviour QMI.Transport

  @impl QMI.Transport
  def start_link(_opts) do
    {:error, :not_implemented}
  end

  @impl QMI.Transport
  def send(_handle, _service_id, _client_id, _payload), do: {:error, :not_implemented}

  @impl QMI.Transport
  def close(_handle), do: :ok
end

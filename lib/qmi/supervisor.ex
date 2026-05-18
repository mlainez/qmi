# SPDX-FileCopyrightText: 2021 Frank Hunleth
# SPDX-FileCopyrightText: 2021 Matt Ludwigs
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.Supervisor do
  @moduledoc """
  Main supervisor for QMI processes
  """

  use Supervisor

  @typedoc """
  QMI Supervisor options

  * `:ifname` - the network interface name. i.e. `"wwan0"`.
  * `:device_path` - the path to the QMI control device for the
    `:qmux` transport. Defaults to `"/dev/cdc-wdm<index>"` where
    `index` matches the `ifname` index. Ignored when `:transport` is
    `:qrtr`.
  * `:transport` - which wire transport to use:

      * `:qmux` — cdc-wdm / `wwan*qmi*` chardev path used by USB
        modems and any in-kernel modem that exposes a cdc-wdm-style
        chardev. Requires `:device_path`.
      * `:qrtr` — `AF_QIPCRTR` sockets, used by in-kernel Qualcomm
        modems whose firmware publishes QMI services on the IPC
        Router (msm8953 / sdm632 — Fairphone 3+ falls here).

    Auto-detected when omitted: if `:device_path` matches a QMUX
    chardev pattern (`/dev/cdc-wdm*` or `/dev/wwan*qmi*`) the
    transport is `:qmux`; otherwise it's `:qrtr`.

  * `:name` - an optional name for this GenServer.
  * `:indication_callback` - a function that is ran when an
    indication is received from QMI.
  """
  @type transport() :: :qmux | :qrtr

  @type options() :: [
          ifname: String.t(),
          device_path: Path.t(),
          transport: transport(),
          name: atom(),
          indication_callback: QMI.indication_callback_fun()
        ]

  @doc """
  Start the supervisor

  The `:name` option is required and will be the QMI supervisor process. Pass
  this name to all functions that have a `qmi` parameter.
  """
  @spec start_link(options()) :: Supervisor.on_start()
  def start_link(options) do
    real_options = derive_options(options)
    name = Keyword.fetch!(real_options, :name)

    Supervisor.start_link(__MODULE__, real_options, name: name)
  end

  @impl Supervisor
  def init(init_args) do
    transport = Keyword.fetch!(init_args, :transport)
    driver_args = Keyword.put(init_args, :transport_mod, transport_module(transport))

    # The CTL-service client-id cache is QMUX-only — QRTR has no
    # equivalent of CTL.GetClientId, so when the QRTR transport is in
    # play we just don't start the cache. `QMI.ClientIDCache.get_client_id`
    # falls back to `{:ok, 0}` when its GenServer isn't running.
    children =
      case transport do
        :qmux -> [{QMI.ClientIDCache, init_args}, {QMI.Driver, driver_args}]
        :qrtr -> [{QMI.Driver, driver_args}]
      end

    Supervisor.init(children, strategy: :one_for_one)
  end

  ## ---- option derivation ----------------------------------------

  defp derive_options(options) do
    options
    |> derive_device_path()
    |> derive_transport()
  end

  defp derive_device_path(options) do
    case {Keyword.get(options, :device_path), Keyword.get(options, :ifname)} do
      {nil, ifname} when is_binary(ifname) ->
        case ifname_to_control_path(ifname) do
          nil -> options
          path -> Keyword.put(options, :device_path, path)
        end

      _ ->
        options
    end
  end

  defp derive_transport(options) do
    Keyword.put_new_lazy(options, :transport, fn ->
      case Keyword.get(options, :device_path) do
        nil -> :qrtr
        path -> if qmux_device?(path), do: :qmux, else: :qrtr
      end
    end)
  end

  # Standard cdc-wdm chardev names and the in-kernel WWAN-subsystem-
  # exposed QMI chardevs are QMUX. Everything else — including a
  # missing path — defaults to QRTR.
  defp qmux_device?(path) do
    String.starts_with?(path, "/dev/cdc-wdm") or
      String.match?(path, ~r"^/dev/wwan\d+qmi\d+$")
  end

  defp transport_module(:qmux), do: QMI.Transport.QMUX
  defp transport_module(:qrtr), do: QMI.Transport.QRTR

  defp ifname_to_control_path("wwan" <> index), do: "/dev/cdc-wdm" <> index
  defp ifname_to_control_path(_), do: nil
end

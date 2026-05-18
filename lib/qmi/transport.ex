defmodule QMI.Transport do
  @moduledoc """
  Behaviour for QMI wire transports.

  A transport owns the underlying file-descriptor / socket that QMI
  messages cross to reach the modem firmware. It hides the differences
  between:

    * QMUX over a chardev — `/dev/cdc-wdm*` (USB modems) or
      `/dev/wwan*qmi*` (in-kernel modems via CONFIG_RPMSG_WWAN_CTRL),
      where every byte of a QMUX-framed message is written to one fd
      and every read returns the next framed message.

    * QRTR — Qualcomm IPC Router via `AF_QIPCRTR` sockets, where each
      QMI service lives at its own `(node, port)` address and the
      library has to look up services and route per message.

  Implementations are responsible for:

    * accepting QMI messages from `QMI.Driver` in their service+client
      form and getting them to the right destination on the wire;
    * delivering inbound messages back to the driver via
      `{:qmi_in, transport_handle, service_id, qmi_bytes}` so the
      driver can match transactions and run indication callbacks.

  See `QMI.Transport.QMUX` (cdc-wdm / wwan-chardev path) and
  `QMI.Transport.QRTR` (in-kernel modem on Qualcomm SoCs) for the two
  built-in implementations.
  """

  @typedoc """
  Opaque per-transport handle returned by `start_link/1`. Passed back
  in to `send/3` and tags inbound `{:qmi_in, …}` messages so the
  driver can demux when more than one transport runs concurrently.
  """
  @type handle :: term()

  @typedoc """
  Options each transport implementation will pick its needs from.
  Common keys:

    * `:owner` — pid that receives `{:qmi_in, …}` notifications.
                 Defaults to the calling process.
    * `:name`  — optional registered name for the transport process.
  """
  @type options :: keyword()

  @callback start_link(options) :: GenServer.on_start()

  @doc """
  Send one QMI service-payload to the modem. `service_id`/`client_id`
  identify the recipient and `payload` is the raw bytes starting at
  the QMI control flags (i.e. *without* any outer QMUX header — the
  transport adds whatever framing/routing its wire needs).
  """
  @callback send(handle, service_id :: non_neg_integer(), client_id :: non_neg_integer(), payload :: binary()) ::
              :ok | {:error, term()}

  @doc """
  Gracefully close the transport (closes the underlying fd/socket and
  stops the GenServer).
  """
  @callback close(handle) :: :ok
end

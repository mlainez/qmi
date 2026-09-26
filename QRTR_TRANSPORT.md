# QRTR transport for QMI

## Why

`qmi` historically targets USB modems that present a `/dev/cdc-wdm*`
chardev (Quectel EC25, Sierra EM7565, …). The driver writes
QMUX-framed bytes to that fd and reads framed bytes back.

In-kernel modems on Qualcomm SoCs (e.g. the MSM8953 mpss firmware on
the Fairphone 3+) **don't expose a cdc-wdm-style chardev**. They
publish each QMI service (WDS, DMS, NAS, UIM, IPA, LTE, …) as a
separate `(node, port)` address on the **Qualcomm IPC Router (QRTR)**.
The Linux kernel exposes QRTR to userspace via `AF_QIPCRTR` sockets
(socket family 42, present in `/proc/net/protocols` whenever the
`qrtr` modules are built in).

This branch (`qrtr-transport`) introduces a second wire transport
side-by-side with the existing chardev path, so the same `QMI.call/3`
API works on either kind of modem.

## Architecture

```
QMI.Supervisor
  └─ QMI.Driver       (transaction bookkeeping, indication dispatch)
       │
       └─ delegates wire I/O via the QMI.Transport behaviour to:
            ├─ QMI.Transport.QMUX   — current cdc-wdm / wwan-chardev path
            └─ QMI.Transport.QRTR   — new AF_QIPCRTR path (this branch)
```

`QMI.Transport` is a tiny behaviour:

* `start_link(opts)` → `{:ok, handle}`
* `send(handle, service_id, client_id, payload)` — payload is the QMI
  service message *starting at the control flags*, without any outer
  QMUX header. The transport adds whatever framing/routing its wire
  needs.
* inbound messages come back to the owner as
  `{:qmi_in, handle, service_id, client_id, bytes}`.

The two wires diverge in semantics — chardev is byte-stream, QRTR is
packet-oriented and address-per-service — but the QMI driver above
only sees the same behaviour, so it can stay transport-agnostic.

## Status

* `QMI.Driver` talks to the wire only through `QMI.Transport`.
  `QMI.Transport.QMUX` is the extracted cdc-wdm path;
  `QMI.Transport.QRTR` is the `AF_QIPCRTR` path.
* `QMI.Supervisor` picks the transport from `:transport`, or
  auto-detects it from `:device_path` (`/dev/cdc-wdm*` and
  `/dev/wwan*qmi*` are QMUX, anything else QRTR).
* The driver restarts a transport that fails to open or exits, with
  exponential backoff (1 s doubling to 30 s), and answers calls with
  `{:error, :transport_unavailable}` meanwhile. Calls for a service
  the modem hasn't announced yet return
  `{:error, {:service_not_found, service_id}}` instead of crashing.
* A LOC (location) codec, `QMI.Codec.LOC`, is included.
* The sibling `vintage_net_qmi` fork (same branch name) passes
  `transport: :qrtr` through.

Not verified on hardware in this revision: the driver error handling
and LOC codec fixes were only tested on a host with a fake transport.

## Why pure-Elixir (no C port)

Erlang/OTP 28's `:socket` module already accepts arbitrary `AF_*`
family numbers, and a quick probe on the FP3+ confirms that
`:socket.open(42, :dgram, 0)` opens the socket cleanly. The QRTR
sockaddr requires `(family, node, port)` rather than `(family, port)`
— solvable with `:socket.bind/2`'s native sockaddr form or by passing
a raw binary. No native code needed for the wire; this transport
stays a single small Elixir module.

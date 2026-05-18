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
  `{:qmi_in, handle, service_id, bytes}`.

The two wires diverge in semantics — chardev is byte-stream, QRTR is
packet-oriented and address-per-service — but the QMI driver above
only sees the same behaviour, so it can stay transport-agnostic.

## Status (current commit)

* `lib/qmi/transport.ex`         — behaviour definition (final).
* `lib/qmi/transport/qmux.ex`    — stub. Will eventually replace the
  inline `DevBridge` usage in `QMI.Driver`. Until then, the existing
  driver path is untouched and USB-modem users see zero change.
* `lib/qmi/transport/qrtr.ex`    — skeleton. Opens the AF_QIPCRTR
  socket and stops. The control-packet parsing, service table, and
  `sendto`/`recvfrom` plumbing all marked TODO.

Nothing in this branch is wired into `QMI.Driver` yet. Existing
behaviour is preserved verbatim.

## Roadmap

1. **Discovery prototype** (next session) — flesh out `Transport.QRTR`
   to:
   * send `QRTR_TYPE_NEW_LOOKUP` for `(service=*, instance=*)`,
   * parse `QRTR_TYPE_NEW_SERVER` / `DEL_SERVER` control packets,
   * maintain the `services` routing table,
   * expose `lookup(service_id)` so a test can confirm the FP3+ modem's
     QMI services are discovered.

2. **Round-trip prototype** — call a known QMI service (e.g. DMS
   Get IDs) and decode the response. This proves the wire format
   works without an outer QMUX header.

3. **Driver delegation** — refactor `QMI.Driver` to call
   `QMI.Transport.<impl>.send/4` instead of `DevBridge.write/2` and
   accept `{:qmi_in, _, _, _}` instead of `{:dev_bridge, _, :read, _}`.
   Extract the current cdc-wdm code path into `QMI.Transport.QMUX`
   1:1, no logic change.

4. **Supervisor auto-detect** — when `:transport` isn't set, pick
   QMUX if `:device_path` is a regular file under `/dev/cdc-wdm*` or
   `/dev/wwan*qmi*`, QRTR otherwise. Explicit `transport: :qrtr |
   :qmux` overrides.

5. **vintage_net_qmi integration** — same `qrtr-transport` branch on
   the sibling fork passes `transport: :qrtr` through when configured.

## Why pure-Elixir (no C port)

Erlang/OTP 28's `:socket` module already accepts arbitrary `AF_*`
family numbers, and a quick probe on the FP3+ confirms that
`:socket.open(42, :dgram, 0)` opens the socket cleanly. The QRTR
sockaddr requires `(family, node, port)` rather than `(family, port)`
— solvable with `:socket.bind/2`'s native sockaddr form or by passing
a raw binary. No native code needed for the wire; this transport
stays a single small Elixir module.

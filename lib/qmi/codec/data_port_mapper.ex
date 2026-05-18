# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.Codec.DataPortMapper do
  @moduledoc """
  Codec for the QMI Data Port Mapper (DPM) service (`0x2F`).

  In-kernel Qualcomm modems on SoCs that use IPA-style data paths
  (msm8953 / sdm632 — Fairphone 3+) require the AP to register its
  hardware data endpoint with the modem before any `WDS` data-plane
  operation will be accepted. Without an `Open Port` call, `WDS Set
  Data Format`, `WDS Bind Mux Data Port`, and `WDS Start Network`
  all return `:invalid_operation` or `:internal`.

  This module implements just enough of DPM to issue an `Open Port`
  for a single embedded hardware data port — that is the path
  ModemManager uses on `net_driver=ipa` modems.
  """

  @dpm_service_id 0x2F
  @open_port 0x0020

  @doc """
  Build a request to open a single hardware data port on the modem.

  Parameters:

    * `endpoint_type` — `QMI_DATA_ENDPOINT_TYPE_*`. Use `4` (embedded)
      for in-kernel modems on msm8953 / sdm632.
    * `interface_number` — typically `1` for the embedded modem.
    * `rx_endpoint_id` — IPA RX endpoint id, read at runtime from
      `/sys/devices/platform/.../ipa/modem/rx_endpoint_id` (`5` on
      msm8953 ipa2-lite).
    * `tx_endpoint_id` — IPA TX endpoint id (`4` on msm8953).
  """
  @spec open_hardware_port(non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ::
          QMI.request()
  def open_hardware_port(endpoint_type, interface_number, rx_endpoint_id, tx_endpoint_id) do
    # TLV 0x11 = Hardware Data Ports — array (u8 count + elements of
    # {endpoint_type:u32, iface_num:u32, rx_ep:u32, tx_ep:u32}).
    elem =
      <<endpoint_type::little-32, interface_number::little-32, rx_endpoint_id::little-32,
        tx_endpoint_id::little-32>>

    tlv_value = <<1>> <> elem
    tlv = <<0x11, byte_size(tlv_value)::little-16>> <> tlv_value
    size = byte_size(tlv)

    %{
      service_id: @dpm_service_id,
      payload: [<<@open_port::little-16, size::little-16>>, tlv],
      decode: &parse_open_port_resp/1
    }
  end

  defp parse_open_port_resp(
         <<@open_port::little-16, _size::little-16, 0x02, _rl::little-16, 0::little-16,
           0::little-16, _rest::binary>>
       ),
       do: {:ok, %{}}

  defp parse_open_port_resp(
         <<@open_port::little-16, _size::little-16, 0x02, _rl::little-16, _qmi_err::little-16,
           err::little-16, _rest::binary>>
       ),
       do: {:error, QMI.Codes.decode_error_code(err)}

  defp parse_open_port_resp(_other), do: {:error, :unexpected_response}
end

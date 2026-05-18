# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.DataPortMapper do
  @moduledoc """
  High-level API for the QMI Data Port Mapper (DPM) service.

  See `QMI.Codec.DataPortMapper` for context. In short: in-kernel
  Qualcomm modems that route data through the IPA hardware accelerator
  require the AP to call `Open Port` with the IPA's RX/TX endpoint IDs
  before any `WDS` data-plane operation will succeed.
  """

  alias QMI.Codec

  @doc """
  Open a single embedded hardware data port on the modem.

  See `QMI.Codec.DataPortMapper.open_hardware_port/4`.
  """
  @spec open_hardware_port(QMI.name(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ::
          {:ok, map()} | {:error, atom()}
  def open_hardware_port(qmi, endpoint_type, interface_number, rx_endpoint_id, tx_endpoint_id) do
    Codec.DataPortMapper.open_hardware_port(endpoint_type, interface_number, rx_endpoint_id, tx_endpoint_id)
    |> QMI.call(qmi)
  end
end

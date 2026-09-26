# SPDX-FileCopyrightText: 2020 Jon Carstens
# SPDX-FileCopyrightText: 2021 Frank Hunleth
# SPDX-FileCopyrightText: 2021 Matt Ludwigs
# SPDX-FileCopyrightText: 2023 Liv Cella
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.Message do
  @moduledoc false

  alias QMI.Codes

  @type type() :: :response | :indication | :request | :compound | :none | :reserved

  @type t() :: %{
          type: type(),
          transaction_id: 0..65_535,
          service_id: 0..255,
          message: binary(),
          code: :success | :failure,
          error: 0..65_535 | atom()
        }

  @spec decode(binary()) :: {:ok, t()} | {:error, :bad_qmux_frame}
  def decode(<<0x01, _len::little-16, _flags, service, client, bin::binary>>),
    do: parse(service, client, bin)

  def decode(_), do: {:error, :bad_qmux_frame}

  @doc """
  Parse a QMI service message given the already-known
  `service_id`/`client_id` (e.g. supplied out-of-band by a transport
  like QRTR that carries them in the socket address rather than in a
  QMUX header).

  `qmi_msg` is the QMI service message itself —
  `<<type(1), txn(little-N), msg_id(little-16), msg_len(little-16),
    tlvs::binary>>` — i.e. exactly the bytes that follow the 3-byte
  QMUX per-service header in a chardev-transported frame.
  """
  @spec parse(non_neg_integer(), non_neg_integer(), binary()) ::
          {:ok, t()} | {:error, :bad_qmi_message}
  def parse(service, _client, qmi_msg) when is_binary(qmi_msg) do
    transaction_size = if service == 0x00, do: 8, else: 16

    case qmi_msg do
      <<type, transaction::little-size(^transaction_size), message_body::binary>> ->
        message =
          %{
            service_id: service,
            type: message_type(service, type),
            message: message_body,
            transaction_id: transaction
          }
          |> get_codes()

        {:ok, message}

      _ ->
        {:error, :bad_qmi_message}
    end
  end

  # types for control service
  defp message_type(0x00, 0x00), do: :request
  defp message_type(0x00, 0x01), do: :response
  defp message_type(0x00, 0x02), do: :indication
  defp message_type(0x00, _), do: :reserved

  # types for services other than control
  defp message_type(_service_id, 0x00), do: :request
  defp message_type(_service_id, 0x01), do: :compound
  defp message_type(_service_id, 0x02), do: :response
  defp message_type(_service_id, 0x04), do: :indication
  defp message_type(_service_id, _), do: :none

  defp get_codes(
         %{
           type: :response,
           message:
             <<_message_id::little-16, _message_size::little-16, 0x02, 0x04::little-16,
               code::little-16, error::little-16, _rest::binary>>
         } = message
       ) do
    message
    |> Map.put(:code, Codes.decode_result_code(code))
    |> Map.put(:error, Codes.decode_error_code(error))
  end

  defp get_codes(message), do: message
end

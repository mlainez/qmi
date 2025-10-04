# SPDX-FileCopyrightText: 2025 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.Codec.Profile do
  @moduledoc """
  Codec for profile management service requests

  This module provides functions to create QMI requests for managing
  cellular network profiles, including querying profile lists and
  retrieving profile settings.
  """

  @get_profile_settings 0x002B
  @get_profile_list 0x002A

  @type profile_type :: :profile_type_3gpp | :profile_type_3gpp2 | :profile_type_epc

  @typedoc """
  PDP (Packet Data Protocol) type for the profile
  """
  @type pdp_type :: :ipv4 | :ppp | :ipv6 | :ipv4v6 | :unknown

  @typedoc """
  Authentication method for the profile
  """
  @type auth_method :: :none | :pap | :chap | :pap_or_chap | :unknown

  @typedoc """
  Profile settings returned by get_profile_settings
  """
  @type profile_settings :: %{
          optional(:apn) => String.t(),
          optional(:pdp_type) => pdp_type(),
          optional(:username) => String.t(),
          optional(:password) => String.t(),
          optional(:auth) => auth_method()
        }

  @typedoc """
  Profile entry returned by get_profile_list
  """
  @type profile_entry :: %{
          profile_type: profile_type(),
          index: non_neg_integer(),
          name: String.t()
        }

  @doc """
  Get settings for a specific profile.

  Example:

      QMI.Codec.Profile.get_profile_settings(3, :profile_type_3gpp)

  This builds a QMI request map that you can send with your
  QMI transport (`QMI.call/2` or equivalent).
  """
  @spec get_profile_settings(integer(), profile_type()) :: QMI.request()
  def get_profile_settings(index, type \\ :profile_type_3gpp) do
    type_byte = encode_profile_type(type)
    # TLV 0x01: profile info (type + index)
    tlv = <<0x01, 0x02::little-16, type_byte, index>>
    size = byte_size(tlv)

    %{
      service_id: 0x01,
      payload: [
        <<@get_profile_settings::little-16, size::little-16>>,
        tlv
      ],
      decode: &parse_get_profile_settings_resp/1
    }
  end

  @doc """
  Request a list of available profiles for a given profile type.

  Supported profile types:
    * :profile_type_3gpp
    * :profile_type_3gpp2
    * :profile_type_epc
  """
  @spec get_profile_list(profile_type()) :: QMI.request()
  def get_profile_list(type \\ :profile_type_3gpp) do
    type_byte = encode_profile_type(type)
    tlv = <<0x01, 0x01::little-16, type_byte>>
    size = byte_size(tlv)

    %{
      service_id: 0x01,
      payload: [
        <<@get_profile_list::little-16, size::little-16>>,
        tlv
      ],
      decode: &parse_get_profile_list_resp/1
    }
  end

  # --- internal parsing ---

  defp parse_get_profile_settings_resp(
         <<@get_profile_settings::little-16, size::little-16, values::binary-size(size)>>
       ) do
    {:ok, parse_profile_settings_tlvs(values, %{})}
  end

  defp parse_get_profile_settings_resp(_), do: {:error, :unexpected_response}

  defp parse_profile_settings_tlvs(<<>>, parsed), do: parsed

  # APN (0x10)
  defp parse_profile_settings_tlvs(
         <<0x10, len::little-16, apn::binary-size(len), rest::binary>>,
         parsed
       ) do
    parse_profile_settings_tlvs(rest, Map.put(parsed, :apn, apn))
  end

  # PDP type (0x11)
  defp parse_profile_settings_tlvs(
         <<0x11, 0x01::little-16, pdp_type, rest::binary>>,
         parsed
       ) do
    pdp =
      case pdp_type do
        0x00 -> :ipv4
        0x01 -> :ppp
        0x02 -> :ipv6
        0x03 -> :ipv4v6
        _ -> :unknown
      end

    parse_profile_settings_tlvs(rest, Map.put(parsed, :pdp_type, pdp))
  end

  # Username (0x12)
  defp parse_profile_settings_tlvs(
         <<0x12, len::little-16, user::binary-size(len), rest::binary>>,
         parsed
       ) do
    parse_profile_settings_tlvs(rest, Map.put(parsed, :username, user))
  end

  # Password (0x13)
  defp parse_profile_settings_tlvs(
         <<0x13, len::little-16, pass::binary-size(len), rest::binary>>,
         parsed
       ) do
    parse_profile_settings_tlvs(rest, Map.put(parsed, :password, pass))
  end

  # Auth (0x14)
  defp parse_profile_settings_tlvs(
         <<0x14, 0x01::little-16, auth, rest::binary>>,
         parsed
       ) do
    method =
      case auth do
        0x00 -> :none
        0x01 -> :pap
        0x02 -> :chap
        0x03 -> :pap_or_chap
        _ -> :unknown
      end

    parse_profile_settings_tlvs(rest, Map.put(parsed, :auth, method))
  end

  # Skip unknown TLVs
  defp parse_profile_settings_tlvs(
         <<_t, len::little-16, _v::binary-size(len), rest::binary>>,
         parsed
       ) do
    parse_profile_settings_tlvs(rest, parsed)
  end

  defp parse_get_profile_list_resp(
         <<@get_profile_list::little-16, size::little-16, values::binary-size(size)>>
       ) do
    {:ok, parse_profile_list_tlvs(values, [])}
  end

  defp parse_get_profile_list_resp(_), do: {:error, :unexpected_response}

  defp parse_profile_list_tlvs(<<>>, profiles), do: profiles

  # Profile list TLV (0x10)
  defp parse_profile_list_tlvs(
         <<0x10, len::little-16, rest::binary-size(len), remaining::binary>>,
         profiles
       ) do
    parsed_profiles = parse_profiles(rest, [])
    parse_profile_list_tlvs(remaining, profiles ++ parsed_profiles)
  end

  defp parse_profile_list_tlvs(
         <<_type, len::little-16, _skip::binary-size(len), rest::binary>>,
         profiles
       ) do
    parse_profile_list_tlvs(rest, profiles)
  end

  defp parse_profiles(<<>>, acc), do: Enum.reverse(acc)

  defp parse_profiles(
         <<ptype, pindex, name_len, name::binary-size(name_len), rest::binary>>,
         acc
       ) do
    profile = %{
      profile_type: decode_profile_type(ptype),
      index: pindex,
      name: name
    }

    parse_profiles(rest, [profile | acc])
  end

  defp decode_profile_type(0x00), do: :profile_type_3gpp
  defp decode_profile_type(0x01), do: :profile_type_3gpp2
  defp decode_profile_type(0x02), do: :profile_type_epc

  defp encode_profile_type(:profile_type_3gpp), do: 0x00
  defp encode_profile_type(:profile_type_3gpp2), do: 0x01
  defp encode_profile_type(:profile_type_epc), do: 0x02
end

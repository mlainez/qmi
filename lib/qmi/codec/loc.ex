# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.Codec.LOC do
  @moduledoc """
  Codec for the QMI **Location** service (service id `0x10`).

  This is what ModemManager talks to when it exposes
  `org.freedesktop.ModemManager1.Modem.Location` on Qualcomm modems.
  The service is asymmetric: requests get an immediate
  `Operation Result` ack and the actual data (current mode after a
  Set, the position fix, etc.) arrives later as an indication.

  Messages implemented:

    * `register_events/1` — `LOC_REG_EVENTS` (0x0021), bit-mask of
      `QmiLocEventRegistrationFlag` (position report, GNSS SV info,
      NMEA, …). You must register before any indication fires.
    * `start/1` — `LOC_START` (0x0022). Opens a tracking session at a
      given recurrence (`:periodic` or `:single_fix`) and reporting
      interval.
    * `stop/1` — `LOC_STOP` (0x0023).
    * `set_operation_mode/1` — `LOC_SET_OPERATION_MODE` (0x004A).
      Picks `:default | :msb | :msa | :standalone | :cellid | :wwan`.

  Indications decoded by `parse_indication/1`:

    * Position Report (0x0024) — lat/lon/alt/speed/heading/accuracy
      and the timestamp.
    * GNSS SV Info (0x0025) — per-satellite SNR / azimuth / elevation
      / constellation / used-in-fix bit.
  """

  require Logger
  import Bitwise

  @loc_service_id 0x10

  # Messages
  @reg_events 0x0021
  @start_msg 0x0022
  @stop_msg 0x0023
  @set_operation_mode 0x004A

  # Indications
  @position_report_ind 0x0024
  @gnss_sv_info_ind 0x0025

  # Event registration bit flags (u64). Subset of QmiLocEventRegistrationFlag
  # — exposed as atoms.
  @event_flags %{
    position_report: 1 <<< 0,
    gnss_satellite_info: 1 <<< 1,
    nmea: 1 <<< 2,
    engine_state: 1 <<< 9,
    fix_session_state: 1 <<< 10
  }

  @operation_mode %{
    default: 1,
    msb: 2,
    msa: 3,
    standalone: 4,
    cellid: 5,
    wwan: 6
  }

  @session_status %{
    0 => :success,
    1 => :in_progress,
    2 => :general_failure,
    3 => :timeout,
    4 => :user_ended,
    5 => :bad_parameter,
    6 => :phone_offline,
    # The libqmi enum also names 6 as ENGINE_LOCKED — we keep
    # :phone_offline since the modem reuses the value.
    7 => :engine_locked
  }

  @system %{
    1 => :gps,
    2 => :galileo,
    3 => :sbas,
    4 => :compass,
    5 => :glonass,
    6 => :qzss,
    7 => :irnss
  }

  @type event_flag ::
          :position_report
          | :gnss_satellite_info
          | :nmea
          | :engine_state
          | :fix_session_state

  @type operation_mode ::
          :default | :msb | :msa | :standalone | :cellid | :wwan

  @type position_indication :: %{
          name: :position_report,
          service_id: 0x10,
          indication_id: 0x0024,
          session_status: atom(),
          session_id: byte() | nil,
          latitude: float() | nil,
          longitude: float() | nil,
          altitude_msl: float() | nil,
          altitude_ellipsoid: float() | nil,
          speed: float() | nil,
          heading: float() | nil,
          accuracy: float() | nil,
          vertical_accuracy: float() | nil,
          hdop: float() | nil,
          pdop: float() | nil,
          vdop: float() | nil,
          utc_timestamp: integer() | nil,
          datetime: DateTime.t() | nil
        }

  @type satellite :: %{
          system: atom(),
          sv_id: non_neg_integer(),
          elevation: float(),
          azimuth: float(),
          snr: float(),
          used_in_fix: boolean(),
          healthy: boolean()
        }

  @type gnss_sv_indication :: %{
          name: :gnss_sv_info,
          service_id: 0x10,
          indication_id: 0x0025,
          satellites: [satellite()]
        }

  # ---- Requests ----------------------------------------------------------

  @doc """
  Build a `Register Events` request. `flags` is a list of
  `t:event_flag/0` atoms; bits are OR'd into the u64 mask the modem
  expects.
  """
  @spec register_events([event_flag()]) :: QMI.request()
  def register_events(flags) when is_list(flags) do
    mask =
      Enum.reduce(flags, 0, fn flag, acc ->
        Map.fetch!(@event_flags, flag) ||| acc
      end)

    body = <<0x01, 0x08::little-16, mask::little-64>>

    %{
      service_id: @loc_service_id,
      payload:
        <<@reg_events::little-16, byte_size(body)::little-16, body::binary>>,
      decode: &parse_operation_result_only/1
    }
  end

  @doc """
  Start a tracking session. Options:

    * `:session_id` — u8 used to correlate indications with this
      session (default `1`).
    * `:recurrence` — `:periodic` (default) or `:single_fix`.
    * `:interval_ms` — minimum interval between position reports
      (default `1000`).
  """
  @spec start(keyword()) :: QMI.request()
  def start(opts \\ []) do
    session_id = Keyword.get(opts, :session_id, 1)
    recurrence = encode_recurrence(Keyword.get(opts, :recurrence, :periodic))
    interval_ms = Keyword.get(opts, :interval_ms, 1_000)

    tlvs =
      <<
        # Session ID
        0x01, 0x01::little-16, session_id,
        # Fix recurrence
        0x10, 0x04::little-16, recurrence::little-32,
        # Minimum interval between position reports (ms)
        0x13, 0x04::little-16, interval_ms::little-32
      >>

    %{
      service_id: @loc_service_id,
      payload: <<@start_msg::little-16, byte_size(tlvs)::little-16, tlvs::binary>>,
      decode: &parse_operation_result_only/1
    }
  end

  @doc "Stop the tracking session matching `session_id` (default `1`)."
  @spec stop(byte()) :: QMI.request()
  def stop(session_id \\ 1) do
    tlvs = <<0x01, 0x01::little-16, session_id>>

    %{
      service_id: @loc_service_id,
      payload: <<@stop_msg::little-16, byte_size(tlvs)::little-16, tlvs::binary>>,
      decode: &parse_operation_result_only/1
    }
  end

  @doc """
  Set the operation mode (`:default | :msb | :msa | :standalone |
  :cellid | :wwan`). The actual mode-change confirmation arrives later
  as an indication with the same message id.
  """
  @spec set_operation_mode(operation_mode()) :: QMI.request()
  def set_operation_mode(mode) when is_map_key(@operation_mode, mode) do
    value = Map.fetch!(@operation_mode, mode)
    tlvs = <<0x01, 0x04::little-16, value::little-32>>

    %{
      service_id: @loc_service_id,
      payload:
        <<@set_operation_mode::little-16, byte_size(tlvs)::little-16, tlvs::binary>>,
      decode: &parse_operation_result_only/1
    }
  end

  # ---- Indication dispatch ----------------------------------------------

  @doc """
  Parse an indication payload (raw QMI message bytes).

  Returns `{:ok, indication_map}` for indication types we know
  (`:position_report`, `:gnss_sv_info`), `{:error, :invalid_indication}`
  otherwise.
  """
  @spec parse_indication(binary()) ::
          {:ok, position_indication() | gnss_sv_indication()} | {:error, :invalid_indication}
  def parse_indication(<<@position_report_ind::little-16, size::little-16, tlvs::binary-size(size)>>) do
    {:ok, parse_position_report(tlvs)}
  end

  def parse_indication(<<@gnss_sv_info_ind::little-16, size::little-16, tlvs::binary-size(size)>>) do
    {:ok, parse_gnss_sv_info(tlvs)}
  end

  def parse_indication(_), do: {:error, :invalid_indication}

  # ---- Response shape ---------------------------------------------------

  # LOC responses are just QMI Operation Result (TLV 0x02, u32 result
  # + u16 error code) — we don't care which message it came from
  # since the actual data shows up in an indication later. Return
  # `:ok` on success, `{:error, code}` otherwise.
  defp parse_operation_result_only(<<_msg_id::little-16, _len::little-16, tlvs::binary>>) do
    case find_tlv(tlvs, 0x02) do
      <<0x00, 0x00, 0x00, 0x00>> -> :ok
      <<_result::little-16, code::little-16>> -> {:error, code}
      _ -> {:error, :no_result_tlv}
    end
  end

  # ---- Position-report parsing ------------------------------------------

  defp parse_position_report(tlvs), do: walk_position_tlvs(tlvs, init_position())

  defp init_position do
    %{
      name: :position_report,
      service_id: @loc_service_id,
      indication_id: @position_report_ind,
      session_status: :unknown,
      session_id: nil,
      latitude: nil,
      longitude: nil,
      altitude_msl: nil,
      altitude_ellipsoid: nil,
      speed: nil,
      heading: nil,
      accuracy: nil,
      vertical_accuracy: nil,
      hdop: nil,
      pdop: nil,
      vdop: nil,
      utc_timestamp: nil,
      datetime: nil
    }
  end

  defp walk_position_tlvs(<<>>, acc), do: acc

  defp walk_position_tlvs(<<tag::8, len::little-16, val::binary-size(len), rest::binary>>, acc) do
    walk_position_tlvs(rest, apply_position_tlv(acc, tag, val))
  end

  defp walk_position_tlvs(_, acc), do: acc

  defp apply_position_tlv(acc, 0x01, <<status::little-32>>),
    do: %{acc | session_status: Map.get(@session_status, status, :unknown)}

  defp apply_position_tlv(acc, 0x02, <<session_id::8>>), do: %{acc | session_id: session_id}
  defp apply_position_tlv(acc, 0x10, <<v::float-little-64>>), do: %{acc | latitude: v}
  defp apply_position_tlv(acc, 0x11, <<v::float-little-64>>), do: %{acc | longitude: v}
  defp apply_position_tlv(acc, 0x12, <<v::float-little-32>>), do: %{acc | accuracy: v}
  defp apply_position_tlv(acc, 0x18, <<v::float-little-32>>), do: %{acc | speed: v}
  defp apply_position_tlv(acc, 0x1A, <<v::float-little-32>>), do: %{acc | altitude_ellipsoid: v}
  defp apply_position_tlv(acc, 0x1B, <<v::float-little-32>>), do: %{acc | altitude_msl: v}
  defp apply_position_tlv(acc, 0x1C, <<v::float-little-32>>), do: %{acc | vertical_accuracy: v}
  defp apply_position_tlv(acc, 0x20, <<v::float-little-32>>), do: %{acc | heading: v}

  defp apply_position_tlv(acc, 0x24, <<pdop::float-little-32, hdop::float-little-32, vdop::float-little-32>>),
    do: %{acc | pdop: pdop, hdop: hdop, vdop: vdop}

  defp apply_position_tlv(acc, 0x25, <<utc_ms::little-64>>) do
    %{acc | utc_timestamp: utc_ms, datetime: utc_to_datetime(utc_ms)}
  end

  defp apply_position_tlv(acc, _tag, _val), do: acc

  # ---- GNSS SV info parsing ---------------------------------------------

  defp parse_gnss_sv_info(tlvs) do
    sats =
      case find_tlv(tlvs, 0x10) do
        <<count::8, rest::binary>> -> parse_satellites(rest, count, [])
        _ -> []
      end

    %{
      name: :gnss_sv_info,
      service_id: @loc_service_id,
      indication_id: @gnss_sv_info_ind,
      satellites: sats
    }
  end

  # Per-satellite element (28 bytes packed little-endian):
  #   u32 valid info
  #   u32 system
  #   u16 satellite id
  #   u8  health status
  #   u32 satellite status
  #   u8  navigation data
  #   f32 elevation degrees
  #   f32 azimuth degrees
  #   f32 SNR (BHz)
  defp parse_satellites(_bin, 0, acc), do: Enum.reverse(acc)

  defp parse_satellites(
         <<_valid::little-32, system::little-32, sv_id::little-16, health::8,
           sat_status::little-32, _nav::8, elev::float-little-32, azim::float-little-32,
           snr::float-little-32, rest::binary>>,
         n,
         acc
       ) do
    sat = %{
      system: Map.get(@system, system, :unknown),
      sv_id: sv_id,
      elevation: elev,
      azimuth: azim,
      snr: snr,
      used_in_fix: (sat_status &&& 0x01) == 0x01,
      healthy: health == 1
    }

    parse_satellites(rest, n - 1, [sat | acc])
  end

  defp parse_satellites(_, _, acc), do: Enum.reverse(acc)

  # ---- Helpers ----------------------------------------------------------

  defp encode_recurrence(:periodic), do: 1
  defp encode_recurrence(:single_fix), do: 2
  defp encode_recurrence(other) when is_integer(other), do: other

  defp find_tlv(<<>>, _tag), do: nil

  defp find_tlv(<<tag::8, len::little-16, val::binary-size(len), _rest::binary>>, tag),
    do: val

  defp find_tlv(<<_tag::8, len::little-16, _val::binary-size(len), rest::binary>>, target),
    do: find_tlv(rest, target)

  defp find_tlv(_, _), do: nil

  # QMI LOC position reports use "milliseconds since GPS epoch
  # (1980-01-06 00:00:00 UTC)" minus leap seconds. We don't have the
  # leap seconds TLV in all reports; approximate using current Unix
  # leap-second offset (18 s as of 2017-01-01, unchanged through 2026).
  @gps_epoch_unix 315_964_800
  @leap_seconds 18

  defp utc_to_datetime(ms) when is_integer(ms) and ms > 0 do
    unix_ms = ms + @gps_epoch_unix * 1000 - @leap_seconds * 1000

    case DateTime.from_unix(div(unix_ms, 1000), :second) do
      {:ok, dt} -> dt
      _ -> nil
    end
  end

  defp utc_to_datetime(_), do: nil
end

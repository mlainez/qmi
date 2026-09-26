# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.Codec.LOCTest do
  use ExUnit.Case, async: true

  alias QMI.Codec.LOC

  describe "requests" do
    test "register_events/1 encodes the u64 event mask" do
      request = LOC.register_events([:position_report, :gnss_satellite_info])

      assert request.service_id == 0x10

      assert IO.iodata_to_binary(request.payload) ==
               <<0x21, 0x00, 0x0B, 0x00, 0x01, 0x08, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0>>
    end

    test "register_events/1 uses libqmi bit positions for engine/fix-session state" do
      request = LOC.register_events([:nmea, :engine_state, :fix_session_state])

      # nmea = 1 <<< 2, engine_state = 1 <<< 7, fix_session_state = 1 <<< 8
      assert IO.iodata_to_binary(request.payload) ==
               <<0x21, 0x00, 0x0B, 0x00, 0x01, 0x08, 0x00, 0x84, 0x01, 0, 0, 0, 0, 0, 0>>
    end

    test "start/1 defaults" do
      request = LOC.start()

      assert IO.iodata_to_binary(request.payload) ==
               <<0x22, 0x00, 0x12, 0x00, 0x01, 0x01, 0x00, 0x01, 0x10, 0x04, 0x00, 0x01, 0x00,
                 0x00, 0x00, 0x13, 0x04, 0x00, 0xE8, 0x03, 0x00, 0x00>>
    end

    test "start/1 with options" do
      request = LOC.start(session_id: 7, recurrence: :single_fix, interval_ms: 5_000)

      assert IO.iodata_to_binary(request.payload) ==
               <<0x22, 0x00, 0x12, 0x00, 0x01, 0x01, 0x00, 0x07, 0x10, 0x04, 0x00, 0x02, 0x00,
                 0x00, 0x00, 0x13, 0x04, 0x00, 0x88, 0x13, 0x00, 0x00>>
    end

    test "stop/1" do
      assert IO.iodata_to_binary(LOC.stop(3).payload) ==
               <<0x23, 0x00, 0x04, 0x00, 0x01, 0x01, 0x00, 0x03>>
    end

    test "set_operation_mode/1" do
      assert IO.iodata_to_binary(LOC.set_operation_mode(:standalone).payload) ==
               <<0x4A, 0x00, 0x07, 0x00, 0x01, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00>>

      assert IO.iodata_to_binary(LOC.set_operation_mode(:msb).payload) ==
               <<0x4A, 0x00, 0x07, 0x00, 0x01, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00>>
    end

    test "responses decode the operation result" do
      request = LOC.start()

      assert request.decode.(<<0x22, 0x00, 0x07, 0x00, 0x02, 0x04, 0x00, 0, 0, 0, 0>>) == :ok

      assert request.decode.(<<0x22, 0x00, 0x07, 0x00, 0x02, 0x04, 0x00, 1, 0, 0x1A, 0>>) ==
               {:error, 0x1A}

      assert request.decode.(<<0x22, 0x00, 0x00, 0x00>>) == {:error, :no_result_tlv}
    end
  end

  describe "position report indication" do
    test "parses a full fix" do
      tlvs =
        <<0x01, 0x04::little-16, 0::little-32>> <>
          <<0x02, 0x01::little-16, 1>> <>
          <<0x10, 0x08::little-16, 50.5::float-little-64>> <>
          <<0x11, 0x08::little-16, 4.25::float-little-64>> <>
          <<0x12, 0x04::little-16, 12.0::float-little-32>> <>
          <<0x18, 0x04::little-16, 1.5::float-little-32>> <>
          <<0x1A, 0x04::little-16, 150.0::float-little-32>> <>
          <<0x1B, 0x04::little-16, 100.0::float-little-32>> <>
          <<0x1C, 0x04::little-16, 8.0::float-little-32>> <>
          <<0x20, 0x04::little-16, 90.0::float-little-32>> <>
          <<0x24, 0x0C::little-16, 2.0::float-little-32, 1.0::float-little-32,
            1.5::float-little-32>> <>
          <<0x25, 0x08::little-16, 1_700_000_000_123::little-64>> <>
          <<0x2C, 0x07::little-16, 3, 5::little-16, 12::little-16, 70::little-16>> <>
          <<0x2D, 0x01::little-16, 0>>

      msg = <<0x24, 0x00, byte_size(tlvs)::little-16, tlvs::binary>>

      assert {:ok, pos} = LOC.parse_indication(msg)

      assert pos == %{
               name: :position_report,
               service_id: 0x10,
               indication_id: 0x24,
               session_status: :success,
               session_id: 1,
               latitude: 50.5,
               longitude: 4.25,
               altitude_msl: 100.0,
               altitude_ellipsoid: 150.0,
               speed: 1.5,
               heading: 90.0,
               accuracy: 12.0,
               vertical_accuracy: 8.0,
               hdop: 1.0,
               pdop: 2.0,
               vdop: 1.5,
               utc_timestamp: 1_700_000_000_123,
               datetime: ~U[2023-11-14 22:13:20Z],
               satellites_used: [5, 12, 70]
             }
    end

    test "in-progress report without a position" do
      tlvs = <<0x01, 0x04::little-16, 1::little-32, 0x02, 0x01::little-16, 1>>
      msg = <<0x24, 0x00, byte_size(tlvs)::little-16, tlvs::binary>>

      assert {:ok, pos} = LOC.parse_indication(msg)
      assert pos.session_status == :in_progress
      assert pos.latitude == nil
      assert pos.longitude == nil
      assert pos.datetime == nil
      assert pos.satellites_used == []
    end

    test "session status 7 is engine_locked" do
      tlvs = <<0x01, 0x04::little-16, 7::little-32>>
      msg = <<0x24, 0x00, byte_size(tlvs)::little-16, tlvs::binary>>

      assert {:ok, %{session_status: :engine_locked}} = LOC.parse_indication(msg)
    end

    test "is routed by QMI.Codec.Indication" do
      tlvs = <<0x01, 0x04::little-16, 0::little-32>>
      body = <<0x24, 0x00, byte_size(tlvs)::little-16, tlvs::binary>>

      assert {:ok, %{name: :position_report}} =
               QMI.Codec.Indication.parse(%{service_id: 0x10, message: body})
    end
  end

  describe "GNSS SV info indication" do
    defp sat(system, sv_id, health, status, elev, azim, snr) do
      <<0xFF::little-32, system::little-32, sv_id::little-16, health, status::little-32, 0x01,
        elev::float-little-32, azim::float-little-32, snr::float-little-32>>
    end

    test "parses the satellite list" do
      list =
        <<3>> <>
          sat(1, 7, 1, 3, 61.0, 210.0, 38.0) <>
          sat(6, 205, 0, 2, 10.0, 45.0, 0.0) <>
          sat(7, 194, 1, 1, 5.0, 180.0, 12.5)

      tlvs = <<0x01, 0x01::little-16, 0, 0x10, byte_size(list)::little-16, list::binary>>
      msg = <<0x25, 0x00, byte_size(tlvs)::little-16, tlvs::binary>>

      assert {:ok, sv} = LOC.parse_indication(msg)
      assert sv.name == :gnss_sv_info
      assert sv.indication_id == 0x25

      assert sv.satellites == [
               %{
                 system: :gps,
                 sv_id: 7,
                 status: :tracking,
                 elevation: 61.0,
                 azimuth: 210.0,
                 snr: 38.0,
                 healthy: true
               },
               %{
                 system: :bds,
                 sv_id: 205,
                 status: :searching,
                 elevation: 10.0,
                 azimuth: 45.0,
                 snr: 0.0,
                 healthy: false
               },
               %{
                 system: :qzss,
                 sv_id: 194,
                 status: :idle,
                 elevation: 5.0,
                 azimuth: 180.0,
                 snr: 12.5,
                 healthy: true
               }
             ]
    end

    test "missing list TLV yields no satellites" do
      tlvs = <<0x01, 0x01::little-16, 0>>
      msg = <<0x25, 0x00, byte_size(tlvs)::little-16, tlvs::binary>>

      assert {:ok, %{satellites: []}} = LOC.parse_indication(msg)
    end
  end

  test "unknown indications are rejected" do
    assert LOC.parse_indication(<<0x26, 0x00, 0x00, 0x00>>) == {:error, :invalid_indication}
    assert LOC.parse_indication(<<0x24>>) == {:error, :invalid_indication}
  end
end

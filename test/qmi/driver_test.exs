# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.DriverTest do
  use ExUnit.Case, async: true

  defmodule FakeTransport do
    @moduledoc false
    # Test double for QMI.Transport. Behaviour is scripted through an
    # Agent passed in `:control`:
    #
    #   * `:start` — `:ok` or `{:error, reason}` for the next start_link
    #   * `:send`  — the value `send/4` returns
    #
    # Every sent message is forwarded to `:test` as
    # `{:fake_sent, transport_pid, service_id, qmi_msg}`.
    @behaviour QMI.Transport
    use GenServer

    @impl QMI.Transport
    def start_link(opts) do
      case Agent.get(opts[:control], & &1.start) do
        :ok -> GenServer.start_link(__MODULE__, opts)
        {:error, _} = error -> error
      end
    end

    @impl QMI.Transport
    def send(pid, service_id, _client_id, msg), do: GenServer.call(pid, {:send, service_id, msg})

    @impl QMI.Transport
    def close(pid), do: GenServer.stop(pid)

    @impl GenServer
    def init(opts) do
      Kernel.send(opts[:test], {:fake_started, self()})
      {:ok, Map.new(opts)}
    end

    @impl GenServer
    def handle_call({:send, service_id, msg}, _from, state) do
      Kernel.send(state.test, {:fake_sent, self(), service_id, msg})
      {:reply, Agent.get(state.control, & &1.send), state}
    end
  end

  setup context do
    {:ok, control} = Agent.start_link(fn -> %{start: :ok, send: :ok} end)
    qmi = Module.concat(__MODULE__, "QMI#{System.unique_integer([:positive])}")

    start = Map.get(context, :start, :ok)
    Agent.update(control, &%{&1 | start: start})

    driver =
      start_supervised!(
        {QMI.Driver,
         name: qmi,
         transport_mod: FakeTransport,
         transport_opts: [control: control, test: self()],
         transport_retry_ms: 20}
      )

    %{qmi: qmi, driver: driver, control: control}
  end

  defp loc_request, do: QMI.Codec.LOC.stop(1)

  test "round trip through the transport", %{qmi: qmi, driver: driver} do
    assert_receive {:fake_started, transport}
    task = Task.async(fn -> QMI.Driver.call(qmi, 0, loc_request()) end)

    assert_receive {:fake_sent, ^transport, 0x10,
                    <<0x00, txn::little-16, 0x23, 0x00, 0x04, 0x00, 0x01, 0x01, 0x00, 0x01>>}

    response = <<0x02, txn::little-16, 0x23, 0x00, 0x07, 0x00, 0x02, 0x04, 0x00, 0, 0, 0, 0>>
    send(driver, {:qmi_in, transport, 0x10, 0, response})

    assert Task.await(task) == :ok
  end

  test "transport send errors are returned to the caller", %{
    qmi: qmi,
    driver: driver,
    control: control
  } do
    assert_receive {:fake_started, _transport}
    Agent.update(control, &%{&1 | send: {:error, {:service_not_found, 0x10}}})

    assert QMI.Driver.call(qmi, 0, loc_request()) == {:error, {:service_not_found, 0x10}}
    assert Process.alive?(driver)

    # and the driver keeps working once the service shows up
    Agent.update(control, &%{&1 | send: :ok})
    task = Task.async(fn -> QMI.Driver.call(qmi, 0, loc_request(), timeout: 50) end)
    assert_receive {:fake_sent, _, 0x10, _}
    assert Task.await(task) == {:error, :timeout}
  end

  @tag start: {:error, :eafnosupport}
  test "transport start failure is retried instead of crashing", %{
    qmi: qmi,
    driver: driver,
    control: control
  } do
    refute_received {:fake_started, _}
    assert QMI.Driver.call(qmi, 0, loc_request()) == {:error, :transport_unavailable}
    assert Process.alive?(driver)

    Agent.update(control, &%{&1 | start: :ok})
    assert_receive {:fake_started, _transport}, 1_000
    assert Process.alive?(driver)
  end

  test "transport exit fails pending calls and restarts the transport", %{
    qmi: qmi,
    driver: driver
  } do
    assert_receive {:fake_started, transport}
    task = Task.async(fn -> QMI.Driver.call(qmi, 0, loc_request()) end)
    assert_receive {:fake_sent, ^transport, _, _}
    # make sure the driver has registered the pending transaction
    _ = :sys.get_state(driver)

    Process.exit(transport, :kill)

    assert Task.await(task) == {:error, :transport_down}
    assert_receive {:fake_started, new_transport}, 1_000
    assert new_transport != transport
    assert Process.alive?(driver)
  end

  test "late failure response for a timed-out request is ignored", %{qmi: qmi, driver: driver} do
    assert_receive {:fake_started, transport}
    assert QMI.Driver.call(qmi, 0, loc_request(), timeout: 20) == {:error, :timeout}
    assert_receive {:fake_sent, ^transport, _, <<0x00, txn::little-16, _::binary>>}

    failure = <<0x02, txn::little-16, 0x23, 0x00, 0x07, 0x00, 0x02, 0x04, 0x00, 1, 0, 0x1A, 0>>
    send(driver, {:qmi_in, transport, 0x10, 0, failure})

    # Driver must survive and still answer calls
    assert QMI.Driver.call(qmi, 0, loc_request(), timeout: 20) == {:error, :timeout}
    assert Process.alive?(driver)
  end
end

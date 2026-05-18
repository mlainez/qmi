# SPDX-FileCopyrightText: 2021 Frank Hunleth
# SPDX-FileCopyrightText: 2021 Matt Ludwigs
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.ClientIDCache do
  @moduledoc false
  use GenServer

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(init_args) do
    qmi = Keyword.fetch!(init_args, :name)

    GenServer.start_link(__MODULE__, init_args, name: name(qmi))
  end

  @spec get_client_id(module(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, atom()}
  def get_client_id(qmi, service_id) do
    # When QMI.Supervisor is running a non-QMUX transport (QRTR, for
    # in-kernel modems) it omits this cache entirely — the QMI CTL
    # service that allocates per-service client IDs doesn't exist on
    # QRTR; each socket *is* the client. Fall back to a constant 0 so
    # the high-level service modules don't need to know which
    # transport is in play.
    case GenServer.whereis(name(qmi)) do
      nil -> {:ok, 0}
      _pid -> GenServer.call(name(qmi), {:get_client_id, qmi, service_id})
    end
  end

  defp name(qmi) do
    Module.concat(qmi, ClientIDCache)
  end

  @impl GenServer
  def init(_init_args) do
    {:ok, %{}}
  end

  @impl GenServer
  def handle_call({:get_client_id, qmi, service_id}, _from, state) do
    case state[service_id] do
      nil ->
        request = QMI.Codec.Control.get_client_id(service_id)

        case QMI.Driver.call(qmi, 0, request, timeout: 4_000) do
          {:ok, client_id} ->
            new_state = Map.put(state, service_id, client_id)
            {:reply, {:ok, client_id}, new_state}

          error ->
            {:reply, error, state}
        end

      client_id ->
        {:reply, {:ok, client_id}, state}
    end
  end
end

# SPDX-FileCopyrightText: 2025 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule QMI.Profile do
  @moduledoc """
  Provides commands related to profile management
  """

  alias QMI.Codec

  @doc """
  Get settings for a specific profile.

  ## Examples

      iex> QMI.Profile.get_profile_settings(MyApp.QMI, 3, :profile_type_3gpp)
      {:ok, %{apn: "internet", pdp_type: :ipv4, username: "user"}}

  """
  @spec get_profile_settings(QMI.name(), integer(), Codec.Profile.profile_type()) ::
          {:ok, map()} | {:error, atom()}
  def get_profile_settings(qmi, index, type \\ :profile_type_3gpp) do
    Codec.Profile.get_profile_settings(index, type)
    |> QMI.call(qmi)
  end

  @doc """
  Request a list of available profiles for a given profile type.

  ## Examples

      iex> QMI.Profile.get_profile_list(MyApp.QMI, :profile_type_3gpp)
      {:ok, [%{profile_type: :profile_type_3gpp, index: 1, name: "internet"}]}

  """
  @spec get_profile_list(QMI.name(), Codec.Profile.profile_type()) ::
          {:ok, [map()]} | {:error, atom()}
  def get_profile_list(qmi, type \\ :profile_type_3gpp) do
    Codec.Profile.get_profile_list(type)
    |> QMI.call(qmi)
  end
end

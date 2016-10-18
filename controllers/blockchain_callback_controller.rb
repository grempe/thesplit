###############################################################################
#
# thesplit - An API server to support the secure sharing of secrets.
# Copyright (c) 2016  Glenn Rempe
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################

# Endpoint for browser Content Security Policy (CSP) Reports
class BlockchainCallbackController < ApplicationController
  # Tierion Blockchain Subscription Callback
  #
  # Sample Payload
  #
  # {
  #   "id"=>"57a6b24046f09ed12f13c2b6",
  #   "merkleRoot"=>"59475c7ae20a4fadf106c8820fd36634123ca6d2c9a07fbfc1148cb850c12c93",
  #   "transactionId"=>"609eb7df1bd56b67f7fed347c7696ce3aaa0bc0dc06b3ff3fb2fb6e22d00b1f0",
  #   "startTimestamp"=>"2016-08-07T03:50:00.069Z",
  #   "endTimestamp"=>"2016-08-07T04:00:00.043Z"
  # }
  #
  post '/' do
    param :id, String, required: true, min_length: 24, max_length: 24,
                       format: settings.hex_regex

    param :merkleRoot, String, required: true, min_length: 64, max_length: 64,
                               format: settings.hex_regex

    param :transactionId, String, required: true, min_length: 64, max_length: 64,
                                  format: settings.hex_regex

    param :startTimestamp, String, required: true
    param :endTimestamp, String, required: true

    BlockchainGetReceiptsWorker.perform_async

    return success_json
  end
end

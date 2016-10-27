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

require 'spec_helper'

RSpec.describe HeartbeatController do
  describe 'GET /heartbeat' do
    context 'with no params' do
      it 'returns 200' do
        get '/'
        expect(last_response.status).to eq 200
      end

      it 'has proper content type' do
        get '/'
        expect(last_response.headers['Content-Type']).to eq('application/json')
      end

      it 'has expected response' do
        get '/'
        expect(json_last_response['status']).to eq('success')
        expect(json_last_response['data']['required_services']).to eq('online')
        expect(json_last_response['data']['redis_ok']).to be true
        expect(json_last_response['data']['redis_ms']).to be < 1.0
        expect(json_last_response['data']['rethinkdb_ok']).to be true
        expect(json_last_response['data']['rethinkdb_ms']).to be < 1.0
        expect(json_last_response['data']['vault_ok']).to be true
        expect(json_last_response['data']['vault_ms']).to be < 1.0
        expect(json_last_response['data']['timestamp']).to be_present
      end
    end
  end
end

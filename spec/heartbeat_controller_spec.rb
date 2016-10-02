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

describe HeartbeatController do
  def app
    described_class
  end

  it 'retrieves a heartbeat' do
    get '/'

    expect(last_response.status).to eq 200
    expect(last_response.headers['Content-Type']).to eq('application/json')

    resp = JSON.parse(last_response.body)
    expect(resp.keys).to eq(%w(status data))
    expect(resp['status']).to eq('success')
    expect(resp['data'].keys.sort).to eq(['redis_ok', 'rethinkdb_ok', 'timestamp', 'vault_ok'])
    expect(resp['data']['redis_ok']).to eq(true)
    expect(resp['data']['rethinkdb_ok']).to eq(true)
    expect(resp['data']['vault_ok']).to eq(true)
  end
end

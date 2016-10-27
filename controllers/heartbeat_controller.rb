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

class HeartbeatController < ApplicationController
  get '/' do
    begin
      redis_start_time = Time.now.utc
      $redis.set('heartbeat', 'ok')
      $redis.expire('heatbeat', 2)
      redis_ok = $redis.get('heartbeat').present? ? true : false
    rescue StandardError
      redis_ok = false
    ensure
      redis_ms = Time.now.utc - redis_start_time
    end

    begin
      rethinkdb_start_time = Time.now.utc

      settings.r.connect(settings.rdb_config) do |conn|
        settings.r.table('heartbeat').insert(
          id: '999',
          heartbeat: 'ok'
        ).run(conn)
      end

      rethinkdb_resp = settings.r.connect(settings.rdb_config) do |conn|
        settings.r.table('heartbeat').get('999').run(conn)
      end

      settings.r.connect(settings.rdb_config) do |conn|
        settings.r.table('heartbeat').get('999').delete().run(conn)
      end

      rethinkdb_ok = rethinkdb_resp['heartbeat'] == 'ok' ? true : false
    rescue StandardError
      rethinkdb_ok = false
    ensure
      rethinkdb_ms = Time.now.utc - rethinkdb_start_time
    end

    begin
      vault_start_time = Time.now.utc
      Vault.logical.write('secret/heartbeat', ok: true)
      vault_ok = Vault.logical.read('secret/heartbeat').present? ? true : false
      Vault.logical.delete('secret/heartbeat')
    rescue StandardError
      vault_ok = false
    ensure
      vault_ms = Time.now.utc - vault_start_time
    end

    # some uptime monitors only allow testing for a single
    # string, and not parsing json. This single string reflects
    # overall service health.
    if redis_ok && rethinkdb_ok && vault_ok
      required_services = 'online'
    else
      required_services = 'offline'
    end

    resp = {
      required_services: required_services,
      redis_ok: redis_ok,
      redis_ms: redis_ms,
      rethinkdb_ok: rethinkdb_ok,
      rethinkdb_ms: rethinkdb_ms,
      vault_ok: vault_ok,
      vault_ms: vault_ms,
      timestamp: Time.now.utc.iso8601
    }

    return success_json(resp)
  end
end

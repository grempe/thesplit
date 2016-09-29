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

describe UsersController do
  def app
    described_class
  end

  before do
    # Test SRP auth with known values
    @username = 'user@example.com'
    @password = 'pet sprain our trial patch bg'
    @keys = SessionKeys.generate(@username, @password)
    @auth = SIRP::Verifier.new(4096).generate_userauth(@keys[:id], @keys[:hex_keys][0])
    @user = {
      id: @keys[:id],
      salt: @auth[:salt],
      verifier: @auth[:verifier],
      enc_public_key: @keys[:nacl_encryption_key_pairs_base64].first[:public_key],
      sign_public_key: @keys[:nacl_signing_key_pairs_base64].first[:public_key]
    }

    # delete the test user before every run if it exists
    app.settings.r.connect(app.settings.rdb_config) do |conn|
      app.settings.r.table('users').get(@user[:id]).delete.run(conn)
    end
  end

  context 'POST /' do
    it 'stores a new user with valid data' do
      app.settings.r.connect(app.settings.rdb_config) do |conn|
        expect(app.settings.r.table('users').get(@user[:id]).run(conn)).to be_nil
      end

      post '/', @user

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data']).to be_nil

      app.settings.r.connect(app.settings.rdb_config) do |conn|
        expect(app.settings.r.table('users').get(@user[:id]).run(conn).keys.sort).to eq(%w(created_at enc_public_key id salt sign_public_key verifier))
      end
    end

    it 'does not store a user with duplicate ID' do
      post '/', @user

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      post '/', @user

      expect(last_response.status).to eq 409
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('Data conflict, user with ID already exists')
      expect(resp['code']).to eq(409)
    end

    it 'returns an error with invalid ID' do
      post '/', @user.merge!(id: 'foo')

      expect(last_response.status).to eq 400
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('id is invalid')
      expect(resp['code']).to eq(400)
    end

    it 'returns an error with invalid salt' do
      post '/', @user.merge!(salt: 'foo')

      expect(last_response.status).to eq 400
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('salt is invalid')
      expect(resp['code']).to eq(400)
    end

    it 'returns an error with invalid verifier' do
      post '/', @user.merge!(verifier: 'foo')

      expect(last_response.status).to eq 400
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('verifier is invalid')
      expect(resp['code']).to eq(400)
    end

    it 'returns an error with invalid enc_public_key' do
      post '/', @user.merge!(enc_public_key: 'foo&')

      expect(last_response.status).to eq 400
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('enc_public_key is invalid')
      expect(resp['code']).to eq(400)
    end

    it 'returns an error with invalid sign_public_key' do
      post '/', @user.merge!(sign_public_key: 'foo&')

      expect(last_response.status).to eq 400
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('sign_public_key is invalid')
      expect(resp['code']).to eq(400)
    end
  end

  context 'OPTIONS /' do
    it 'returns expected result' do
      options '/'

      expect(last_response.headers['Allow']).to eq('POST')
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Length']).to eq('0')
      expect(last_response.body).to eq('')
      expect(last_response.status).to eq 200
    end
  end

  context 'GET /:id' do
    before do
      app.settings.r.connect(app.settings.rdb_config) do |conn|
        app.settings.r.table('users').insert(@user, conflict: 'replace').run(conn)
      end
    end

    it 'retrieves a user with a valid ID' do
      get "/#{@user[:id]}"

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys.sort).to eq(%w(enc_public_key id sign_public_key))
      expect(resp['data']['id']).to eq(@user[:id])
      expect(resp['data']['enc_public_key']).to eq(@user[:enc_public_key])
      expect(resp['data']['sign_public_key']).to eq(@user[:sign_public_key])
    end

    it 'returns an error with invalid ID' do
      get '/foo'

      expect(last_response.status).to eq 400
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('id is invalid')
      expect(resp['code']).to eq(400)
    end
  end

  context 'OPTIONS /:id' do
    it 'returns expected result' do
      options "/#{@user[:id]}"

      expect(last_response.headers['Allow']).to eq('GET')
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Length']).to eq('0')
      expect(last_response.body).to eq('')
      expect(last_response.status).to eq 200
    end
  end

  context 'POST /:id/srp/*' do
    it 'completes two-phase SRP challenge/authenticate' do
      # create a test user
      post '/', @user

      # redis session_key for this ID should be nil
      session_key = "srp:challenge:#{@user[:id]}"
      expect($redis.get(session_key)).to be_nil

      # Generate the A value to start auth
      client = SIRP::Client.new(4096)
      aa = client.start_authentication

      # POST the A (aa) and request a challenge
      post "/#{@user[:id]}/srp/challenge", {aa: aa}

      # Server challenge response should include user `salt` and `B`
      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      expect(JSON.parse($redis.get(session_key)).keys).to eq(%w(challenge proof))
      expect($redis.ttl(session_key)).to be_between(1, 60).inclusive

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys.sort).to eq(%w(bb salt))
      expect(resp['data']['bb'].size).to be_between(512, 2048).inclusive
      expect(resp['data']['salt']).to eq(@user[:salt])

      # process the server challenge and salt
      # must use the same client instance that was created earlier
      client_M = client.process_challenge(@keys[:id], @keys[:hex_keys][0], resp['data']['salt'], resp['data']['bb'])

      # the client should have a 'K' shared secret
      expect(client.K.length).to eq(64)

      # POST the id and M for final authentication
      post "/#{@user[:id]}/srp/authenticate", {mm: client_M}

      # Server challenge response should include H_AMK
      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys.sort).to eq(%w(hamk))
      expect(resp['data']['hamk'].size).to eq(64)
    end
  end

  context 'OPTIONS /:id/srp/challenge' do
    it 'returns expected result' do
      options "/#{@user[:id]}/srp/challenge"

      expect(last_response.headers['Allow']).to eq('POST')
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Length']).to eq('0')
      expect(last_response.body).to eq('')
      expect(last_response.status).to eq 200
    end
  end

  context 'OPTIONS /:id/srp/authenticate' do
    it 'returns expected result' do
      options "/#{@user[:id]}/srp/authenticate"

      expect(last_response.headers['Allow']).to eq('POST')
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Length']).to eq('0')
      expect(last_response.body).to eq('')
      expect(last_response.status).to eq 200
    end
  end
end

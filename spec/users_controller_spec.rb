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
    @username = Faker::Internet.email
    @password = Faker::Internet.password(32)
    @keys = SessionKeys.generate(@username, @password)
    @auth = SIRP::Verifier.new(4096).generate_userauth(@keys[:id], @keys[:hex_keys][0])
    @user = {
      id: @keys[:id],
      srp_salt: @auth[:salt],
      srp_verifier: @auth[:verifier],
      enc_public_key: @keys[:nacl_encryption_key_pairs_base64].first[:public_key],
      sign_public_key: @keys[:nacl_signing_key_pairs_base64].first[:public_key]
    }
  end

  context 'POST /' do
    it 'stores a new user with valid data' do
      post '/', @user

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys.sort).to eq(["blockchain_hash", "created_at", "enc_public_key", "id", "sign_public_key", "verification_hash", "verification_hash_signature_base64", "verify_key_base64"])

      app.settings.r.connect(app.settings.rdb_config) do |conn|
        expect(app.settings.r.table('users').get(@user[:id]).run(conn).keys.sort).to eq(["blockchain_hash", "created_at", "enc_public_key", "id", "sign_public_key", "srp_salt", "srp_verifier", "verification_hash", "verification_hash_signature_base64", "verify_key_base64"])
      end
    end

    it 'returns server signed data that can be cryptographically verified with only public info' do
      post '/', @user

      expect(last_response.status).to eq 200
      resp = JSON.parse(last_response.body)

      # collect the data that will be hashed and signed
      verification_items = [
        resp['data']['id'],
        resp['data']['id'].length,
        resp['data']['enc_public_key'],
        resp['data']['enc_public_key'].length,
        resp['data']['sign_public_key'],
        resp['data']['sign_public_key'].length,
        resp['data']['created_at']
      ].join(':')

      # re-create the SHA256 hash that will be signed
      verification_hash = Digest::SHA256.hexdigest(verification_items)
      expect(resp['data']['verification_hash']).to eq verification_hash

      # Rehydrate the signature public key, and signature, and then test the verification
      verify_key = RbNaCl::VerifyKey.new(Base64.strict_decode64(resp['data']['verify_key_base64']))
      verification_hash_signature = Base64.strict_decode64(resp['data']['verification_hash_signature_base64'])
      verify_key.verify(verification_hash_signature, verification_hash)

      # Verify that the blockchain hash is indeed the SHA256 of the signature bytestring
      # The blockchain_hash is what can actually be found on a BTC OP_RETURN transaction.
      expect(resp['data']['blockchain_hash']).to eq(Digest::SHA256.hexdigest(verification_hash_signature))
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
      post '/', @user.merge!(srp_salt: 'foo')

      expect(last_response.status).to eq 400
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('srp_salt is invalid')
      expect(resp['code']).to eq(400)
    end

    it 'returns an error with duplicate salt' do
      post '/', @user
      expect(last_response.status).to eq 200

      # provide different values for all keys except the one we are testing dups for
      auth = SIRP::Verifier.new(4096).generate_userauth(@keys[:id], @keys[:hex_keys][0])
      post '/', @user.merge!( id: Digest::SHA256.hexdigest('abc123'), enc_public_key: "abc#{@user[:enc_public_key]}", srp_verifier: "#{auth[:verifier]}" )
      expect(last_response.status).to eq 409

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('Data conflict, srp_salt is not unique')
      expect(resp['code']).to eq(409)
    end

    it 'returns an error with invalid verifier' do
      post '/', @user.merge!(srp_verifier: 'foo')

      expect(last_response.status).to eq 400
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('srp_verifier is invalid')
      expect(resp['code']).to eq(400)
    end

    it 'returns an error with duplicate verifier' do
      post '/', @user
      expect(last_response.status).to eq 200

      # provide different values for all keys except the one we are testing dups for
      auth = SIRP::Verifier.new(4096).generate_userauth(@keys[:id], @keys[:hex_keys][0])
      post '/', @user.merge!( id: Digest::SHA256.hexdigest('abc123'), enc_public_key: "abc#{@user[:enc_public_key]}", srp_salt: "#{auth[:salt]}" )
      expect(last_response.status).to eq 409

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('Data conflict, srp_verifier is not unique')
      expect(resp['code']).to eq(409)
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

    it 'returns an error with duplicate enc_public_key' do
      post '/', @user
      expect(last_response.status).to eq 200

      # provide different values for all keys except the one we are testing dups for
      auth = SIRP::Verifier.new(4096).generate_userauth(@keys[:id], @keys[:hex_keys][0])
      post '/', @user.merge!( id: Digest::SHA256.hexdigest('abc123'), sign_public_key: "foo#{@user[:sign_public_key]}", srp_salt: "#{auth[:salt]}", srp_verifier: "#{auth[:verifier]}" )
      expect(last_response.status).to eq 409

      resp = JSON.parse(last_response.body)
      expect(resp['message']).to eq('Data conflict, enc_public_key is not unique')
      expect(resp['code']).to eq(409)
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

    it 'returns an error with duplicate sign_public_key' do
      post '/', @user
      expect(last_response.status).to eq 200

      # provide different values for all keys except the one we are testing dups for
      auth = SIRP::Verifier.new(4096).generate_userauth(@keys[:id], @keys[:hex_keys][0])
      post '/', @user.merge!( id: Digest::SHA256.hexdigest('abc123'), enc_public_key: "abc#{@user[:enc_public_key]}", srp_salt: "#{auth[:salt]}", srp_verifier: "#{auth[:verifier]}" )
      expect(last_response.status).to eq 409

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status message code))
      expect(resp['status']).to eq('error')
      expect(resp['message']).to eq('Data conflict, sign_public_key is not unique')
      expect(resp['code']).to eq(409)
    end
  end

  context 'GET /:id' do
    before do
      post '/', @user
    end

    it 'retrieves a user with a valid ID' do
      get "/#{@user[:id]}"

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys.sort).to eq(["blockchain_hash", "created_at", "enc_public_key", "id", "sign_public_key", "verification_hash", "verification_hash_signature_base64", "verify_key_base64"])
      expect(resp['data']['id']).to eq(@user[:id])
      expect(resp['data']['enc_public_key']).to eq(@user[:enc_public_key])
      expect(resp['data']['sign_public_key']).to eq(@user[:sign_public_key])
    end

    it 'returns server signed data that can be cryptographically verified with only public info' do
      get "/#{@user[:id]}"

      expect(last_response.status).to eq 200
      resp = JSON.parse(last_response.body)

      # collect the data that will be hashed and signed
      verification_items = [
        resp['data']['id'],
        resp['data']['id'].length,
        resp['data']['enc_public_key'],
        resp['data']['enc_public_key'].length,
        resp['data']['sign_public_key'],
        resp['data']['sign_public_key'].length,
        resp['data']['created_at']
      ].join(':')

      # re-create the SHA256 hash that will be signed
      verification_hash = Digest::SHA256.hexdigest(verification_items)
      expect(resp['data']['verification_hash']).to eq verification_hash

      # Rehydrate the signature public key, and signature, and then test the verification
      verify_key = RbNaCl::VerifyKey.new(Base64.strict_decode64(resp['data']['verify_key_base64']))
      verification_hash_signature = Base64.strict_decode64(resp['data']['verification_hash_signature_base64'])
      verify_key.verify(verification_hash_signature, verification_hash)

      # Verify that the blockchain hash is indeed the SHA256 of the signature bytestring
      # The blockchain_hash is what can actually be found on a BTC OP_RETURN transaction.
      expect(resp['data']['blockchain_hash']).to eq(Digest::SHA256.hexdigest(verification_hash_signature))
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
      expect(resp['data'].keys.sort).to eq(%w(bb srp_salt))
      expect(resp['data']['bb'].size).to be_between(512, 2048).inclusive
      expect(resp['data']['srp_salt']).to eq(@user[:srp_salt])

      # process the server challenge and salt
      # must use the same client instance that was created earlier
      client_M = client.process_challenge(@keys[:id], @keys[:hex_keys][0], resp['data']['srp_salt'], resp['data']['bb'])

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
end

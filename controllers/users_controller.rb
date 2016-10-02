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

# Handle all user registration and SRP authentication
class UsersController < ApplicationController
  # POST a new user, pass in TOFU SRP values
  # Expects id, salt, verifier, NaCl enc public_key, NaCl signing public_key
  post '/' do
    param :id, String, required: true, min_length: 64, max_length: 64,
                       format: settings.hex_regex

    param :salt, String, required: true, min_length: 20, max_length: 64,
                         format: settings.hex_regex

    param :verifier, String, required: true, max_length: 1024,
                             format: settings.hex_regex

    param :enc_public_key, String, required: true, max_length: 64,
                                   format: settings.base64_regex

    param :sign_public_key, String, required: true, max_length: 64,
                                    format: settings.base64_regex

    settings.r.connect(settings.rdb_config) do |conn|
      if settings.r.table('users').get(params['id']).run(conn).present?
        halt 409, error_json('Data conflict, user with ID already exists', 409)
      end
    end

    # FIXME : verify the incoming keys by requiring the sender to encrypt
    # and sign data that we can verify now using the keys provided

    created_at = Time.now.utc.iso8601

    # Submit a signed copy of the submitted data to the blockchain
    # to allow independant client verfication.

    verification_items = [
      params['id'],
      params['id'].length,
      params['enc_public_key'],
      params['enc_public_key'].length,
      params['sign_public_key'],
      params['sign_public_key'].length,
      created_at
    ].join(':')

    verification_hash = Digest::SHA256.hexdigest(verification_items)
    verification_hash_signature = settings.signing_key.sign(verification_hash)
    verification_hash_signature_base64 = Base64.strict_encode64(verification_hash_signature)
    # ensure the verification works, or throw an exception
    settings.verify_key.verify(verification_hash_signature, verification_hash)
    blockchain_hash = Digest::SHA256.hexdigest(verification_hash_signature)

    # The critical user data to be sent back to the client along with
    # hashes and signatures needed to later verify the integrity of
    # the encryption and signature public keys for that user. These
    # will allow the owner of an account, or any other party, to
    # independently verify key integrity or detect changes after TOFU.
    resp = { id: params['id'],
             enc_public_key: params['enc_public_key'],
             sign_public_key: params['sign_public_key'],
             created_at: created_at,
             verification_hash: verification_hash,
             verification_hash_signature_base64: verification_hash_signature_base64,
             verify_key_base64: settings.verify_key_base64,
             blockchain_hash: blockchain_hash }

    # Save the user data along with the semi-public srp_salt
    # and the non-public srp_verifier
    settings.r.connect(settings.rdb_config) do |conn|
      settings.r.table('users').insert(
        resp.merge(srp_salt: params['salt'], srp_verifier: params['verifier'])
      ).run(conn)
    end

    # The user data has been saved to the DB, send the hash of its important
    # values to the blockchain for later proof of existence.
    BlockchainSendHashWorker.perform_async(blockchain_hash)

    return success_json(resp)
  end

  options '/' do
    response.headers['Allow'] = 'POST'
    200
  end

  # GET public user info by id
  get '/:id' do
    param :id, String, required: true, min_length: 64, max_length: 64,
                       format: settings.hex_regex

    user = settings.r.connect(settings.rdb_config) do |conn|
      settings.r.table('users').get(params['id']).run(conn)
    end

    raise Sinatra::NotFound if user.blank?

    resp = { id: params['id'] }

    [ 'enc_public_key', 'sign_public_key', 'created_at',
      'verification_hash', 'verification_hash_signature_base64',
      'verify_key_base64', 'blockchain_hash' ].each do |key|
      raise Sinatra::NotFound if user[key].blank?
      resp[key] = user[key]
    end

    return success_json(resp)
  end

  options '/:id' do
    response.headers['Allow'] = 'GET'
    200
  end

  # Client => Server: id, A (aa)
  # Server => Client: salt, B (bb)
  post '/:id/srp/challenge' do
    param :id, String, required: true, min_length: 64, max_length: 64,
                       format: settings.hex_regex

    param :aa, String, required: true, min_length: 1024, max_length: 1024,
                       format: settings.hex_regex

    # look up the user by ID
    user = settings.r.connect(settings.rdb_config) do |conn|
      settings.r.table('users').get(params['id']).run(conn)
    end

    if user.blank? || user['id'].blank? || user['srp_verifier'].blank? || user['srp_salt'].blank?
      halt 401, error_json('unauthorized', 401)
    end

    # Generates B (bb) and other proof attributes needed by the client
    # for the challenge phase
    verifier = SIRP::Verifier.new(4096)
    session = verifier.get_challenge_and_proof(user['id'], user['srp_verifier'], user['srp_salt'], params[:aa])

    # Store the ephemeral challenge and proof temporarily in Redis
    # This state is needed for the SRP authenticate phase to complete.
    # Expire this key automatically after a short duration.
    session_key = "srp:challenge:#{user['id']}"
    $redis.set(session_key, session.to_json)
    $redis.expire(session_key, 5)

    return success_json(salt: session[:challenge][:salt], bb: session[:challenge][:B])
  end

  options '/:id/srp/challenge' do
    response.headers['Allow'] = 'POST'
    200
  end

  # Client => Server: id, M (mm)
  # Server => Client: H(AMK)
  post '/:id/srp/authenticate' do
    param :id, String, required: true, min_length: 64, max_length: 64,
                       format: settings.hex_regex

    param :mm, String, required: true, min_length: 64, max_length: 64,
                       format: settings.hex_regex

    # Retrieve the ephemeral proof and challenge that was stored in Redis.
    pc = $redis.get("srp:challenge:#{params['id']}")

    halt 401, error_json('unauthorized', 401) if pc.blank?

    pch = JSON.parse(pc)

    halt 401, error_json('unauthorized', 401) unless pch.keys.sort == ['challenge', 'proof']

    # Generate server h(AMK), if it is non-nil authentication worked
    # and there will be a client and server shared key in verifier[:K]
    verifier = SIRP::Verifier.new(4096)

    server_H_AMK = verifier.verify_session(pch['proof'], params['mm'])

    halt 401, error_json('unauthorized', 401) if server_H_AMK.blank?

    # Authenticated! : return value to client so client can compare
    # h(AMK) and mutually verify.
    return success_json(hamk: server_H_AMK)
  end

  options '/:id/srp/authenticate' do
    response.headers['Allow'] = 'POST'
    200
  end
end

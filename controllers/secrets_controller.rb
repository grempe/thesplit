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

# App endpoints for /api/v1/secrets/*
class SecretsController < ApplicationController
  post '/' do
    param :id, String, required: true, min_length: 64, max_length: 64,
                       format: settings.hex_regex

    param :box_nonce, String, required: true, min_length: 24, max_length: 64,
                              format: settings.base64_regex

    param :box, String, required: true, min_length: 1,
                        max_length: settings.secrets_max_length,
                        format: settings.base64_regex

    param :scrypt_salt, String, required: true, min_length: 24, max_length: 64,
                                format: settings.base64_regex

    vault_index_key = "secret/#{params['id']}"

    t     = Time.now.utc
    t_exp = t + settings.secrets_expire_in

    obj = { box_nonce: params['box_nonce'],
            box: params['box'],
            scrypt_salt: params['scrypt_salt'],
            created_at: t.iso8601,
            expires_at: t_exp.iso8601 }

    if Vault.logical.read(vault_index_key).present?
      halt 409, error_json('Data conflict, secret with ID already exists', 409)
    end

    one_time_token = vault_token_24h_1x

    # store the value of the one time token in a place we can find it
    Vault.logical.write(vault_index_key, token: one_time_token)

    # Store secret data using the one-time-use token
    # Instantiate a new Vault::Client in order to auth with the one-time token
    vc = Vault::Client.new
    # token num_uses - 1
    vc.auth.token(one_time_token)
    # token num_uses - 1
    vc.logical.write("cubbyhole/#{params['id']}", obj)

    BlockchainSendHashWorker.perform_async(params['id'])

    return success_json(created_at: t.iso8601, expires_at: t_exp.iso8601)
  end

  options '/' do
    response.headers['Allow'] = 'POST'
    200
  end

  delete '/:id' do
    param :id, String, required: true, min_length: 64, max_length: 64,
                       format: settings.hex_regex

    vault_index_key = "secret/#{params['id']}"

    # find and revoke the token, which will also destroy any cubbyhole data
    vault_token = Vault.logical.read(vault_index_key)

    raise Sinatra::NotFound if vault_token.blank? || vault_token.data.blank?

    vc = Vault::Client.new
    # token num_uses - 1
    vc.auth.token(vault_token.data[:token])
    # token num_uses - 1
    # revocation of token also destroys any cubbyhole secrets
    vc.auth_token.revoke_self

    # deleting the index that let us find the token
    Vault.logical.delete(vault_index_key)

    return success_json
  end

  get '/:id' do
    param :id, String, required: true, min_length: 64, max_length: 64,
                       format: settings.hex_regex

    vault_index_key = "secret/#{params['id']}"

    # Retrive the one-time use token using the app token
    vault_token = Vault.logical.read(vault_index_key)

    raise Sinatra::NotFound if vault_token.blank? || vault_token.data.blank?

    # Instantiate a new Vault::Client in order to auth with the one-time token
    vc = Vault::Client.new
    # token num_uses - 1
    vc.auth.token(vault_token.data[:token])
    # token num_uses - 1
    # one-time token private cubbyhole
    vault_secret = vc.logical.read("cubbyhole/#{params['id']}")

    # cleanup the index with the cubbyhole token
    Vault.logical.delete(vault_index_key)

    raise Sinatra::NotFound if vault_secret.blank? || vault_secret.data.blank?

    return success_json(vault_secret.data)
  end

  options '/:id' do
    response.headers['Allow'] = 'GET,DELETE'
    200
  end

  get '/:id/receipt' do
    param :id, String, required: true, min_length: 64, max_length: 64,
                       format: settings.hex_regex

    r = settings.r.connect(settings.rdb_config) do |conn|
      settings.r.table('blockchain').get(params['id']).run(conn)
    end

    raise Sinatra::NotFound if r.blank?

    begin
      hash_item = r['hash_item'] unless r['hash_item'].blank?
      receipt = r['receipt'] unless r['receipt'].blank?
      confirmed = Time.parse(r['confirmed']) unless r['confirmed'].blank?
    rescue StandardError
      halt 500, error_json('server blockchain receipt could not be parsed', 500)
    end

    t_receipt = Tierion::HashApi::Receipt.new(receipt) unless receipt.blank?

    if t_receipt && !t_receipt.valid?
      halt 500, error_json('server receipt is invalid', 500)
    end

    obj = {}
    obj[:hash_item] = hash_item.present? ? hash_item : nil
    obj[:receipt] = t_receipt.present? ? t_receipt : nil
    obj[:confirmed] = confirmed.present? ? confirmed.utc.iso8601 : nil

    return success_json(obj)
  end

  options '/:id/receipt' do
    response.headers['Allow'] = 'GET'
    200
  end

  def vault_token_24h_1x
    # num_uses is 4 since we auth, write, auth, read|delete in normal flow
    opts = { renewable: false,
             ttl: "#{settings.secrets_expire_in}s",
             explicit_max_ttl: "#{settings.secrets_expire_in}s",
             num_uses: 4,
             policies: ['default'] }

    Vault.with_retries(Vault::HTTPError, attempts: 3) do
      t = Vault.auth_token.create(opts)
      return t.auth.client_token
    end
  end
end

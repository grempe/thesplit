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

describe SecretsController do
  def app
    described_class
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

  context 'POST /' do
    before do
      Vault.logical.delete("secret/fc3791ef66c25914a0cb9a32c2debf8d4cc7bd7d0b6545ec50750c0b3bb68f98")
    end

    it 'stores a secret with valid data' do
      client_hash = 'fc3791ef66c25914a0cb9a32c2debf8d4cc7bd7d0b6545ec50750c0b3bb68f98'
      box_nonce = 'LkekKSqdi93MfGE3Ti3LsJaVzziTFWLq'
      box = 'rBIyEoNrKTop8Capp/51dtAlGJs='
      scrypt_salt = 'n1AvpGTPOhP3OWbKmS87NFVtij7Ner2NvqnRymioDWU='

      expect(Vault.logical.read("secret/#{client_hash}")).to be_nil

      post '/',
        id: client_hash,
        box_nonce: box_nonce,
        box: box,
        scrypt_salt: scrypt_salt

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys).to eq(%w(created_at expires_at))

      expect(Vault.logical.read("secret/#{client_hash}").data[:token]).to match(/^[a-f0-9\-]+$/)
    end
  end

  context 'OPTIONS /:id' do
    it 'returns expected result' do
      options '/fc3791ef66c25914a0cb9a32c2debf8d4cc7bd7d0b6545ec50750c0b3bb68f98'

      expect(last_response.headers['Allow']).to eq('GET,DELETE')
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Length']).to eq('0')
      expect(last_response.body).to eq('')
      expect(last_response.status).to eq 200
    end
  end

  context 'GET /:id' do
    before do
      Vault.logical.delete("secret/fc3791ef66c25914a0cb9a32c2debf8d4cc7bd7d0b6545ec50750c0b3bb68f98")
    end

    it 'retrieves a secret' do
      client_hash = 'fc3791ef66c25914a0cb9a32c2debf8d4cc7bd7d0b6545ec50750c0b3bb68f98'
      box_nonce = 'LkekKSqdi93MfGE3Ti3LsJaVzziTFWLq'
      box = 'rBIyEoNrKTop8Capp/51dtAlGJs='
      scrypt_salt = 'n1AvpGTPOhP3OWbKmS87NFVtij7Ner2NvqnRymioDWU='

      expect(Vault.logical.read("secret/#{client_hash}")).to be_nil

      post '/',
        id: client_hash,
        box_nonce: box_nonce,
        box: box,
        scrypt_salt: scrypt_salt

      # has a one-time use token
      expect(Vault.logical.read("secret/#{client_hash}").data[:token]).to match(/^[a-f0-9\-]+$/)

      get "/#{client_hash}"

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys.sort).to eq(%w(box_nonce box scrypt_salt created_at expires_at).sort)
      expect(resp['data']['box_nonce']).to eq(box_nonce)
      expect(resp['data']['box']).to eq(box)
      expect(resp['data']['scrypt_salt']).to eq(scrypt_salt)

      expect(Vault.logical.read("secret/#{client_hash}")).to be_nil

      # the second time should fail
      get "/#{client_hash}"

      expect(last_response.status).to eq 404
    end
  end

  context 'GET /:id/receipt' do
    before do
      @hash_item = { "receipt"=>nil,
                     "id"=>"57b3ea8d3c6819e5786fa85a",
                     "timestamp"=>1471408781,
                     "hash"=>"90ea37fa715946b924ef8b0b0610a6153e2e2d3d895c241336f6be925f40347b"}

      @receipt = { "@context"=>"https://w3id.org/chainpoint/v2",
                  "type"=>"ChainpointSHA256v2",
                  "targetHash"=>"90ea37fa715946b924ef8b0b0610a6153e2e2d3d895c241336f6be925f40347b",
                  "merkleRoot"=>"43425e5816b19992f98e7650f66485218eeb105b881da78432e703684c32a4c3",
                  "proof"=>[{"right"=>"e54ff18231b44f121db4cf4beca99bb7eda69fea0b9211b72a46485e81018376"}],
                  "anchors"=>[{"type"=>"BTCOpReturn", "sourceId"=>"ca3b1f8549029701f7b1d66bacd3784c814fc994d1fc012572ebeeef2c060fea"}]}

      @client_hash = 'fc3791ef66c25914a0cb9a32c2debf8d4cc7bd7d0b6545ec50750c0b3bb68f98'
      @t = Time.now.utc.iso8601
      $redis.hset("blockchain:id:#{@client_hash}", 'hash_item', @hash_item.to_json)
      $redis.hset("blockchain:id:#{@client_hash}", 'receipt', @receipt.to_json)
      $redis.hset("blockchain:id:#{@client_hash}", 'confirmed', @t)
    end

    it 'retrieves a receipt' do
      get "/#{@client_hash}/receipt"
      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys.sort).to eq(%w(confirmed hash_item receipt).sort)
      expect(resp['data']['hash_item']).to eq(@hash_item)
      expect(resp['data']['receipt']).to eq(@receipt)
      expect(resp['data']['confirmed']).to eq(@t)
    end
  end

  context 'DELETE /:id' do
    it 'deletes a secret' do
      client_hash = 'fc3791ef66c25914a0cb9a32c2debf8d4cc7bd7d0b6545ec50750c0b3bb68f98'
      box_nonce = 'LkekKSqdi93MfGE3Ti3LsJaVzziTFWLq'
      box = 'rBIyEoNrKTop8Capp/51dtAlGJs='
      scrypt_salt = 'n1AvpGTPOhP3OWbKmS87NFVtij7Ner2NvqnRymioDWU='

      expect(Vault.logical.read("secret/#{client_hash}")).to be_nil

      post '/',
        id: client_hash,
        box_nonce: box_nonce,
        box: box,
        scrypt_salt: scrypt_salt

      expect(Vault.logical.read("secret/#{client_hash}").data[:token]).to match(/^[a-f0-9\-]+$/)

      delete "/#{client_hash}"

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data']).to be_nil

      expect(Vault.logical.read("secret/#{client_hash}")).to be_nil
    end
  end
end

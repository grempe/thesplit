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
      Vault.logical.delete("secret/#{Digest::SHA256.hexdigest('e8a3fcaf610745d6dae5df8db67bd264')}")
    end

    it 'stores a secret with valid data' do
      blake2sHash = 'e8a3fcaf610745d6dae5df8db67bd264'
      boxNonceB64 = 'LkekKSqdi93MfGE3Ti3LsJaVzziTFWLq'
      boxB64 = 'rBIyEoNrKTop8Capp/51dtAlGJs='
      scryptSaltB64 = 'n1AvpGTPOhP3OWbKmS87NFVtij7Ner2NvqnRymioDWU='

      expect(Vault.logical.read("secret/#{Digest::SHA256.hexdigest(blake2sHash)}")).to be_nil

      post '/',
        id: blake2sHash,
        boxNonceB64: boxNonceB64,
        boxB64: boxB64,
        scryptSaltB64: scryptSaltB64

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys).to eq(%w(id createdAt expiresAt))

      expect(Vault.logical.read("secret/#{Digest::SHA256.hexdigest(blake2sHash)}").data[:token]).to match(/^[a-f0-9\-]+$/)
    end
  end

  context 'OPTIONS /:id' do
    it 'returns expected result' do
      options '/e8a3fcaf610745d6dae5df8db67bd264'

      expect(last_response.headers['Allow']).to eq('GET,DELETE')
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Length']).to eq('0')
      expect(last_response.body).to eq('')
      expect(last_response.status).to eq 200
    end
  end

  context 'GET /:id' do
    before do
      Vault.logical.delete("secret/#{Digest::SHA256.hexdigest('e8a3fcaf610745d6dae5df8db67bd264')}")
    end

    it 'retrieves a secret' do
      blake2sHash = 'e8a3fcaf610745d6dae5df8db67bd264'
      boxNonceB64 = 'LkekKSqdi93MfGE3Ti3LsJaVzziTFWLq'
      boxB64 = 'rBIyEoNrKTop8Capp/51dtAlGJs='
      scryptSaltB64 = 'n1AvpGTPOhP3OWbKmS87NFVtij7Ner2NvqnRymioDWU='

      expect(Vault.logical.read("secret/#{Digest::SHA256.hexdigest(blake2sHash)}")).to be_nil

      post '/',
        id: blake2sHash,
        boxNonceB64: boxNonceB64,
        boxB64: boxB64,
        scryptSaltB64: scryptSaltB64

      # has a one-time use token
      expect(Vault.logical.read("secret/#{Digest::SHA256.hexdigest(blake2sHash)}").data[:token]).to match(/^[a-f0-9\-]+$/)

      get "/#{blake2sHash}"

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys.sort).to eq(%w(boxNonceB64 boxB64 scryptSaltB64).sort)
      expect(resp['data']['boxNonceB64']).to eq(boxNonceB64)
      expect(resp['data']['boxB64']).to eq(boxB64)
      expect(resp['data']['scryptSaltB64']).to eq(scryptSaltB64)

      expect(Vault.logical.read("secret/#{Digest::SHA256.hexdigest(blake2sHash)}")).to be_nil

      # the second time should fail
      get "/#{blake2sHash}"

      expect(last_response.status).to eq 404
    end
  end

  context 'GET /:id/receipt' do
    before do
      @receipt = { "@context"=>"https://w3id.org/chainpoint/v2",
                  "type"=>"ChainpointSHA256v2",
                  "targetHash"=>"90ea37fa715946b924ef8b0b0610a6153e2e2d3d895c241336f6be925f40347b",
                  "merkleRoot"=>"43425e5816b19992f98e7650f66485218eeb105b881da78432e703684c32a4c3",
                  "proof"=>[{"right"=>"e54ff18231b44f121db4cf4beca99bb7eda69fea0b9211b72a46485e81018376"}],
                  "anchors"=>[{"type"=>"BTCOpReturn", "sourceId"=>"ca3b1f8549029701f7b1d66bacd3784c814fc994d1fc012572ebeeef2c060fea"}]}

      @client_hash = 'e8a3fcaf610745d6dae5df8db67bd264'
      @t = Time.now.utc.iso8601
      $redis.hset("blockchain:id:#{Digest::SHA256.hexdigest(@client_hash)}", 'receipt', @receipt.to_json)
      $redis.hset("blockchain:id:#{Digest::SHA256.hexdigest(@client_hash)}", 'confirmed', @t)
    end

    it 'retrieves a receipt' do
      get "/#{@client_hash}/receipt"
      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys.sort).to eq(%w(confirmed_at receipt).sort)
      expect(resp['data']['receipt']).to eq(@receipt)
      expect(resp['data']['confirmed_at']).to eq(@t)
    end
  end

  context 'DELETE /:id' do
    it 'deletes a secret' do
      blake2sHash = 'e8a3fcaf610745d6dae5df8db67bd264'
      boxNonceB64 = 'LkekKSqdi93MfGE3Ti3LsJaVzziTFWLq'
      boxB64 = 'rBIyEoNrKTop8Capp/51dtAlGJs='
      scryptSaltB64 = 'n1AvpGTPOhP3OWbKmS87NFVtij7Ner2NvqnRymioDWU='

      expect(Vault.logical.read("secret/#{Digest::SHA256.hexdigest(blake2sHash)}")).to be_nil

      post '/',
        id: blake2sHash,
        boxNonceB64: boxNonceB64,
        boxB64: boxB64,
        scryptSaltB64: scryptSaltB64

      expect(Vault.logical.read("secret/#{Digest::SHA256.hexdigest(blake2sHash)}").data[:token]).to match(/^[a-f0-9\-]+$/)

      delete "/#{blake2sHash}"

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data']).to be_nil

      expect(Vault.logical.read("secret/#{Digest::SHA256.hexdigest(blake2sHash)}")).to be_nil
    end
  end
end

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

describe 'root' do

  def app
    Sinatra::Application
  end

  context 'GET /' do
    it 'returns expected result' do
      get '/'

      expect(last_response.headers['Content-Type']).to eq('text/html;charset=utf-8')
      expect(last_response.body).to match(/thesplit.is/)
      expect(last_response.status).to eq 200
    end
  end

  context 'OPTIONS /' do
    it 'returns expected result' do
      options '/'

      expect(last_response.headers['Allow']).to eq('HEAD,GET')
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Length']).to eq('0')
      expect(last_response.body).to eq('')
      expect(last_response.status).to eq 200
    end
  end
end

describe 'Secrets' do
  def app
    Sinatra::Application
  end

  context 'OPTIONS /api/v1/secrets' do
    it 'returns expected result' do
      options '/api/v1/secrets'

      expect(last_response.headers['Allow']).to eq('POST')
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Length']).to eq('0')
      expect(last_response.body).to eq('')
      expect(last_response.status).to eq 200
    end
  end

  context 'POST /api/v1/secrets' do
    it 'stores a secret with valid data' do
      blake2sHash = 'e8a3fcaf610745d6dae5df8db67bd264'
      boxNonceB64 = 'LkekKSqdi93MfGE3Ti3LsJaVzziTFWLq'
      boxB64 = 'rBIyEoNrKTop8Capp/51dtAlGJs='
      scryptSaltB64 = 'n1AvpGTPOhP3OWbKmS87NFVtij7Ner2NvqnRymioDWU='

      key = "secrets:#{Digest::SHA256.hexdigest(blake2sHash)}"
      expect($redis.get(key)).to be_nil

      post '/api/v1/secrets',
        blake2sHash: blake2sHash,
        boxNonceB64: boxNonceB64,
        boxB64: boxB64,
        scryptSaltB64: scryptSaltB64

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys).to eq(%w(id createdAt expiresAt))

      redis_value = $redis.get(key)
      redis_value_parsed = JSON.parse(redis_value)
      expect(redis_value_parsed).to eq({'boxNonceB64' => boxNonceB64,
                                        'boxB64' => boxB64,
                                        'scryptSaltB64' => scryptSaltB64})
    end
  end

  context 'OPTIONS /api/v1/secrets/:id' do
    it 'returns expected result' do
      options '/api/v1/secrets/e8a3fcaf610745d6dae5df8db67bd264'

      expect(last_response.headers['Allow']).to eq('GET,DELETE')
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Length']).to eq('0')
      expect(last_response.body).to eq('')
      expect(last_response.status).to eq 200
    end
  end

  context 'GET /api/v1/secrets/:id' do
    it 'retrieves a secret' do
      blake2sHash = 'e8a3fcaf610745d6dae5df8db67bd264'
      boxNonceB64 = 'LkekKSqdi93MfGE3Ti3LsJaVzziTFWLq'
      boxB64 = 'rBIyEoNrKTop8Capp/51dtAlGJs='
      scryptSaltB64 = 'n1AvpGTPOhP3OWbKmS87NFVtij7Ner2NvqnRymioDWU='

      key = "secrets:#{Digest::SHA256.hexdigest(blake2sHash)}"
      expect($redis.get(key)).to be_nil

      post '/api/v1/secrets',
        blake2sHash: blake2sHash,
        boxNonceB64: boxNonceB64,
        boxB64: boxB64,
        scryptSaltB64: scryptSaltB64

      redis_value = $redis.get(key)
      redis_value_parsed = JSON.parse(redis_value)
      expect(redis_value_parsed).to eq({'boxNonceB64' => boxNonceB64,
                                        'boxB64' => boxB64,
                                        'scryptSaltB64' => scryptSaltB64})

      get "/api/v1/secrets/#{blake2sHash}"

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data'].keys).to eq(%w(boxNonceB64 boxB64 scryptSaltB64))
      expect(resp['data']['boxNonceB64']).to eq(boxNonceB64)
      expect(resp['data']['boxB64']).to eq(boxB64)
      expect(resp['data']['scryptSaltB64']).to eq(scryptSaltB64)

      expect($redis.get(key)).to be_nil
    end
  end

  context 'DELETE /api/v1/secrets/:id' do
    it 'deletes a secret' do
      blake2sHash = 'e8a3fcaf610745d6dae5df8db67bd264'
      boxNonceB64 = 'LkekKSqdi93MfGE3Ti3LsJaVzziTFWLq'
      boxB64 = 'rBIyEoNrKTop8Capp/51dtAlGJs='
      scryptSaltB64 = 'n1AvpGTPOhP3OWbKmS87NFVtij7Ner2NvqnRymioDWU='

      key = "secrets:#{Digest::SHA256.hexdigest(blake2sHash)}"
      expect($redis.get(key)).to be_nil

      post '/api/v1/secrets',
        blake2sHash: blake2sHash,
        boxNonceB64: boxNonceB64,
        boxB64: boxB64,
        scryptSaltB64: scryptSaltB64

      redis_value = $redis.get(key)
      redis_value_parsed = JSON.parse(redis_value)
      expect(redis_value_parsed).to eq({'boxNonceB64' => boxNonceB64,
                                        'boxB64' => boxB64,
                                        'scryptSaltB64' => scryptSaltB64})

      delete "/api/v1/secrets/#{blake2sHash}"

      expect(last_response.status).to eq 200
      expect(last_response.headers['Content-Type']).to eq('application/json')

      resp = JSON.parse(last_response.body)
      expect(resp.keys).to eq(%w(status data))
      expect(resp['status']).to eq('success')
      expect(resp['data']).to be_nil

      expect($redis.get(key)).to be_nil
    end
  end
end

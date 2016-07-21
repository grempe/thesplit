require 'spec_helper'

describe 'Secrets' do
  def app
    Sinatra::Application
  end

  before do
    app.settings.redis.flushdb
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

      key = "secrets:#{blake2sHash}"
      expect(app.settings.redis.get(key)).to be_nil

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

      redis_value = app.settings.redis.get(key)
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

      key = "secrets:#{blake2sHash}"
      expect(app.settings.redis.get(key)).to be_nil

      post '/api/v1/secrets',
        blake2sHash: blake2sHash,
        boxNonceB64: boxNonceB64,
        boxB64: boxB64,
        scryptSaltB64: scryptSaltB64

      redis_value = app.settings.redis.get(key)
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

      expect(app.settings.redis.get(key)).to be_nil
    end
  end

  context 'DELETE /api/v1/secrets/:id' do
    it 'deletes a secret' do
      blake2sHash = 'e8a3fcaf610745d6dae5df8db67bd264'
      boxNonceB64 = 'LkekKSqdi93MfGE3Ti3LsJaVzziTFWLq'
      boxB64 = 'rBIyEoNrKTop8Capp/51dtAlGJs='
      scryptSaltB64 = 'n1AvpGTPOhP3OWbKmS87NFVtij7Ner2NvqnRymioDWU='

      key = "secrets:#{blake2sHash}"
      expect(app.settings.redis.get(key)).to be_nil

      post '/api/v1/secrets',
        blake2sHash: blake2sHash,
        boxNonceB64: boxNonceB64,
        boxB64: boxB64,
        scryptSaltB64: scryptSaltB64

      redis_value = app.settings.redis.get(key)
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

      expect(app.settings.redis.get(key)).to be_nil
    end
  end
end

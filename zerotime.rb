require 'sinatra'
require 'sinatra/param'
require 'sinatra/cross_origin'
require 'json'
require 'redis'
require 'simple_uuid'
require 'blake2'

helpers Sinatra::Param

# 24 hours
SECRETS_EXPIRE_SECS = 86_400
URL_SAFE_BASE64_REGEX = /^[a-zA-Z0-9+=\/\-\_]+$/

redis = Redis.new(url: ENV['REDIS_URL'] ||= 'redis://127.0.0.1:6379')

configure do
  # CORS
  enable :cross_origin
end

before do
  content_type :json
end

get '/' do
  content_type :html
  erb :index
end

post '/secret' do
  param :blake2sHash, String, required: true, transform: :downcase,
                              min_length: 64, max_length: 64,
                              format: /^[a-fA-F0-9]+$/

  param :boxNonceB64, String, required: true, min_length: 24, max_length: 64,
                              format: URL_SAFE_BASE64_REGEX

  param :boxB64, String, required: true, min_length: 1, max_length: 1024,
                         format: URL_SAFE_BASE64_REGEX

  param :scryptSaltB64, String, required: true, min_length: 24, max_length: 64,
                                format: URL_SAFE_BASE64_REGEX

  blake2s_hash    = params['blake2sHash']
  box_nonce_b64   = params['boxNonceB64']
  box_b64         = params['boxB64']
  scrypt_salt_b64 = params['scryptSaltB64']

  # Integrity checks on the incoming nonce and secret box data. Ensure the
  # content that will be stored matches exactly what was HMAC'ed on the client
  # using BLAKE2s with a shared pepper.
  b2_pepper = Blake2::Key.from_string('zerotime')
  b2_str = [scrypt_salt_b64, box_nonce_b64, box_b64].join
  b2_hash = Blake2.hex(b2_str, b2_pepper)

  unless b2_hash == blake2s_hash
    err = {
      message: 'Parameter must contain valid hash of required params',
      errors: {
        blake2sHash: 'Parameter must contain valid hash of required params'
      }
    }
    halt 400, err.to_json
  end

  begin
    uuid = SimpleUUID::UUID.new
    t = uuid.to_time
    t_exp = uuid.to_time + SECRETS_EXPIRE_SECS

    key = "zerotime:secret:#{uuid.to_guid}"
    redis.set(key, { boxNonceB64: box_nonce_b64,
                     boxB64: box_b64,
                     scryptSaltB64: scrypt_salt_b64 }.to_json)

    redis.expire(key, SECRETS_EXPIRE_SECS)

    return { uuid: uuid.to_guid,
             created_at: t.utc.iso8601,
             expires_at: t_exp.utc.iso8601 }.to_json
  rescue
    halt 500, { error: 'server error' }.to_json
  end
end

get '/secret/:uuid' do
  param :uuid, String, required: true, min_length: 36, max_length: 36,
                       format: /^[a-f0-9\-]+$/

  begin
    uuid = SimpleUUID::UUID.new(params['uuid'])
  rescue
    raise Sinatra::NotFound
  end

  begin
    key = "zerotime:secret:#{uuid.to_guid}"
    secret = redis.get(key)
    raise Sinatra::NotFound if secret.nil?
    secret_parsed = JSON.parse(secret)
  rescue
    # bad json
    raise Sinatra::NotFound
  ensure
    redis.del(key)
  end

  return { secret: secret_parsed, createdAt: uuid.to_time.utc.iso8601 }.to_json
end

# sinatra-cross_origin : Handle CORS OPTIONS pre-flight
# requests properly. See: https://github.com/britg/sinatra-cross_origin
options '*' do
  response.headers['Allow'] = 'HEAD,GET,PUT,POST,DELETE,OPTIONS'
  response.headers['Access-Control-Allow-Headers'] = 'X-Requested-With, X-HTTP-Method-Override, Content-Type, Cache-Control, Accept'
  200
end

# Sinatra::NotFound handler
not_found do
  err = {
    message: 'Not found',
    errors: {
      server: 'Not found'
    }
  }
  halt 404, err.to_json
end

# Unhandled error handler
error do
  err = {
    message: 'Server error',
    errors: {
      server: 'Server error'
    }
  }
  halt 500, err.to_json
end

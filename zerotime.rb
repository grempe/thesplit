require 'sinatra'
require 'sinatra/cross_origin'
require 'json'
require 'redis'
require 'simple_uuid'
require 'blake2'

# 24 hours
SECRETS_EXPIRE_SECS = 86_400

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
  if params.nil? || params['data'].nil? || params['data'].empty?
    halt 400, { error: 'argument error : no params' }.to_json
  end

  begin
    data = JSON.parse(params['data'])
    if data.nil? || data.empty? || !data.is_a?(Hash)
      halt 400, { error: 'invalid json params, data type error' }.to_json
    end
  rescue
    halt 400, { error: 'invalid json params error, parse fail' }.to_json
  end

  unless data.keys.sort == %w(blake2sHash boxB64 boxNonceB64 scryptSaltB64).sort
    halt 400, { error: 'invalid json params error, missing/extra keys' }.to_json
  end

  unless data['boxB64'].length.between?(1, 1024)
    # 413 : Payload Too Large
    halt 413, { error: 'argument error : payload too large' }.to_json
  end

  # Integrity checks on the incoming nonce and secret box data. Ensure the
  # content that will be stored matches exactly what was HMAC'ed on the client
  # using BLAKE2s with a shared pepper.
  b2_pepper = Blake2::Key.from_string('zerotime')
  b2_str = "#{data['scryptSaltB64']}#{data['boxNonceB64']}#{data['boxB64']}"
  b2_hash = Blake2.hex(b2_str, b2_pepper)

  unless b2_hash == data['blake2sHash']
    halt 400, { error: 'BLAKE2s hash verification error' }.to_json
  end

  begin
    uuid = SimpleUUID::UUID.new
    t = uuid.to_time
    t_exp = uuid.to_time + SECRETS_EXPIRE_SECS

    key = "zerotime:secret:#{uuid.to_guid}"
    redis.set(key, params['data'])
    redis.expire(key, SECRETS_EXPIRE_SECS)

    return { uuid: uuid.to_guid,
             created_at: t.utc.iso8601,
             expires_at: t_exp.utc.iso8601 }.to_json
  rescue
    halt 500, { error: 'server error' }.to_json
  end
end

get '/secret/:uuid' do
  begin
    uuid = SimpleUUID::UUID.new(params['uuid'])
  rescue
    halt 400, { error: 'invalid uuid' }.to_json
  end

  key = "zerotime:secret:#{uuid.to_guid}"
  secret = redis.get(key)
  halt 404, { error: 'not found' }.to_json if secret.nil?
  redis.del(key)
  return { secret: secret, created_at: uuid.to_time.utc.iso8601 }.to_json
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
  halt 404, { error: 'not found' }.to_json
end

# Unhandled error handler
error do
  halt 500, { error: 'server error' }.to_json
end

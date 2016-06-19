require 'sinatra'
require 'sinatra/cross_origin'
require 'json'
require 'redis'
require 'simple_uuid'
require 'blake2'

# 172_800 == 48 hours
SECRETS_EXPIRE_SECS = 172_800

redis = Redis.new(url: ENV['REDIS_URL'] ||= 'redis://127.0.0.1:6379')

configure do
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
  if params.nil? || params['data'].empty?
    halt 400, { error: 'argument error : no data' }.to_json
  end

  begin
    data = JSON.parse(params['data'])
  rescue
    halt 400, { error: 'invalid json params error' }.to_json
  end

  unless data && data['boxBytesB64'] && data['boxBytesB64'].length.between?(1, 1024)
    # 413 : Payload Too Large
    halt 413, { error: 'argument error : payload too large' }.to_json
  end

  # Integrity checks on the incoming nonce and secret box data. Ensure the
  # content that will be stored matches exactly what was HMAC'ed on the client
  # using BLAKE2s with a shared pepper.
  if data && data['nonceBytesB64'] && data['boxBytesB64'] && data['blake2sHash']
    b2_pepper = Blake2::Key.from_string('zerotime')
    b2_hash = Blake2.hex(data['nonceBytesB64'] + data['boxBytesB64'], b2_pepper)

    unless b2_hash == data['blake2sHash']
      halt 400, { error: 'BLAKE2s hash verification error' }.to_json
    end
  else
    halt 400, { error: 'invalid json params error' }.to_json
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
  # Parse the incoming UUID to validate
  begin
    uuid = SimpleUUID::UUID.new(params['uuid'])
  rescue
    halt 400, { error: 'invalid uuid' }.to_json
  end

  key = "zerotime:secret:#{uuid.to_guid}"

  begin
    secret = redis.get(key)
    halt 404, { error: 'not found' }.to_json if secret.nil?
    redis.del(key)

    return { secret: secret, created_at: uuid.to_time.utc.iso8601 }.to_json
  rescue
    halt 404, { error: 'not found' }.to_json
  end
end

# sinatra-cross_origin : Handle CORS OPTIONS pre-flight
# requests properly. See: https://github.com/britg/sinatra-cross_origin
options '*' do
  response.headers['Allow'] = 'HEAD,GET,PUT,POST,DELETE,OPTIONS'
  response.headers['Access-Control-Allow-Headers'] = 'X-Requested-With, X-HTTP-Method-Override, Content-Type, Cache-Control, Accept'
  200
end

# FALL THROUGH ROUTES

get '/*' do
  halt 404, { error: 'not found' }.to_json
end

post '/*' do
  halt 404, { error: 'not found' }.to_json
end

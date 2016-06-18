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

  unless params['data'].length.between?(1, 1024)
    halt 413, { error: 'argument error : too long' }.to_json
  end

  # Integrity checks on the incoming nonce and secret box
  # data. Ensure the Base64 content that will be stored
  # matches what was HMAC'ed on the client using BLAKE2s.
  begin
    data = JSON.parse(params['data'])
  rescue
    halt 400, { error: 'invalid json params error' }.to_json
  end

  if data && data['nonceBytesB64'] && data['boxBytesB64']
    b2_pepper = Blake2::Key.from_string('zerotime')
    b2_hash = Blake2.hex(data['nonceBytesB64'] +
                         data['boxBytesB64'], b2_pepper)
  else
    halt 400, { error: 'invalid json params error' }.to_json
  end

  unless b2_hash == data['blake2sHash']
    halt 400, { error: 'no matching hash error' }.to_json
  end

  begin
    uuid = SimpleUUID::UUID.new
    t = uuid.to_time
    t_exp = uuid.to_time + SECRETS_EXPIRE_SECS

    key = "secret:#{uuid.to_guid}"
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

  key = "secret:#{uuid.to_guid}"

  begin
    secret = redis.get(key)
    halt 404, { error: 'not found' }.to_json if secret.nil?
    redis.del(key)

    return { secret: secret, created_at: uuid.to_time.utc.iso8601 }.to_json
  rescue
    halt 404, { error: 'not found' }.to_json
  end
end

# UNSUPPORTED ROUTES

get '/*' do
  halt 404, { error: 'not found' }.to_json
end

post '/*' do
  halt 404, { error: 'not found' }.to_json
end

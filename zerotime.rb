require 'sinatra'
require 'json'
require 'redis'
require 'simple_uuid'

redis = Redis.new(url: ENV['REDIS_URL'] ||= 'redis://127.0.0.1:6379')

get '/' do
  erb :index
end

post '/secret' do
  content_type :json

  unless params['data']
    halt 400, { error: 'argument error : no data' }.to_json
  end

  unless params['data'].length < 1024
    halt 413, { error: 'argument error : too long' }.to_json
  end

  unless params['data'] =~ /^[a-zA-Z0-9\+\-\_\\]+$/
    halt 400, { error: 'argument error : bad format' }.to_json
  end

  begin
    uuid = SimpleUUID::UUID.new
    key = "secret:#{uuid.to_guid}"
    redis.set(key, params['data'])
    # Expire in 48 hours
    redis.expire(key, 172_800)
    { uuid: uuid.to_guid, created_at: uuid.to_time.utc.iso8601 }.to_json
  rescue
    halt 500, { error: 'server error' }.to_json
  end
end

get '/secret/:uuid' do
  content_type :json

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
    { secret: secret, created_at: uuid.to_time.utc.iso8601 }.to_json
  rescue
    halt 404, { error: 'not found' }.to_json
  end
end

# UNSUPPORTED ROUTES

get '/*' do
  content_type :json
  halt 404, { error: 'not found' }.to_json
end

post '/*' do
  content_type :json
  halt 404, { error: 'not found' }.to_json
end

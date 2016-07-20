require 'sinatra'
require 'sinatra/param'
require 'sinatra/cross_origin'
require 'json'
require 'jsender'
require 'redis'
require 'rbnacl/libsodium'
require 'rbnacl'
require 'blake2'

# http://edgeguides.rubyonrails.org/active_support_core_extensions.html#time
require 'active_support'
require 'active_support/core_ext/object/blank.rb'
require 'active_support/core_ext/numeric'
require 'active_support/core_ext/string/starts_ends_with.rb'
require 'active_support/core_ext/object/try.rb'

# Common JSON response
# http://labs.omniti.com/labs/jsend
# https://github.com/hetznerZA/jsender
include Jsender

helpers Sinatra::Param

SECRETS_EXPIRE_SECS = 30.days

# 2**16
SECRET_MAX_LEN_BYTES = 65_536

BASE64_REGEX = /^[a-zA-Z0-9+=\/\-\_]+$/
HEX_REGEX = /^[a-f0-9]+$/

configure do
  # CORS
  enable :cross_origin
  set :server, :puma

  # Sinatra Param
  # https://github.com/mattt/sinatra-param
  set :raise_sinatra_param_exceptions, true
  disable :show_exceptions
  enable :raise_errors

  set :redis, Redis.new(url: ENV['REDIS_URL'] ||= 'redis://127.0.0.1:6379')
end

configure :production, :development do
  enable :logging
end

before do
  content_type :json
end

get '/' do
  stats_increment('get-root')
  content_type :html
  erb :index
end

get '/api/v1/stats' do
  stats = { timestamp: Time.now.utc.iso8601,
            secrets_created_total: stat_total('post-secret'),
            secrets_created_year: stat_year('post-secret'),
            secrets_created_month: stat_month('post-secret'),
            secrets_created_day: stat_day('post-secret'),
            secrets_created_hour: stat_hour('post-secret'),
            secrets_retrieved_total: stat_total('get-secret-id'),
            secrets_retrieved_year: stat_year('get-secret-id'),
            secrets_retrieved_month: stat_month('get-secret-id'),
            secrets_retrieved_day: stat_day('get-secret-id'),
            secrets_retrieved_hour: stat_hour('get-secret-id')
         }

  return success_json(stats)
end

post '/api/v1/secret' do
  param :blake2sHash, String, required: true, min_length: 32, max_length: 32,
                              format: HEX_REGEX

  param :boxNonceB64, String, required: true, min_length: 24, max_length: 64,
                              format: BASE64_REGEX

  param :boxB64, String, required: true, min_length: 1,
                         max_length: SECRET_MAX_LEN_BYTES, format: BASE64_REGEX

  param :scryptSaltB64, String, required: true, min_length: 24, max_length: 64,
                                format: BASE64_REGEX

  stats_increment('post-secret')

  blake2s_hash    = params['blake2sHash']
  scrypt_salt_b64 = params['scryptSaltB64']
  box_nonce_b64   = params['boxNonceB64']
  box_b64         = params['boxB64']

  unless valid_hash?(blake2s_hash, [scrypt_salt_b64, box_nonce_b64, box_b64])
    halt 400, error_json('Integrity hash mismatch', 400)
  end

  t     = Time.now
  t_exp = t + SECRETS_EXPIRE_SECS
  key   = "zerotime:secret:#{blake2s_hash}"

  unless settings.redis.get(key).blank?
    halt 409, error_json('Data conflict, secret with ID already exists', 409)
  end

  settings.redis.set(key, { boxNonceB64: box_nonce_b64,
                            boxB64: box_b64,
                            scryptSaltB64: scrypt_salt_b64 }.to_json)

  settings.redis.expire(key, SECRETS_EXPIRE_SECS)

  logger.info "POST /api/v1/secret : created id : #{blake2s_hash}"

  return success_json(id: blake2s_hash, createdAt: t.utc.iso8601,
                     expiresAt: t_exp.utc.iso8601)
end

get '/api/v1/secret/:id' do
  # id is 16 Byte blake2s hash of the data that was stored
  param :id, String, required: true, min_length: 32, max_length: 32,
                     format: HEX_REGEX

  stats_increment('get-secret-id')

  key = "zerotime:secret:#{params['id']}"
  sec_json = settings.redis.get(key)

  if sec_json.blank?
    logger.warn "GET /api/v1/secret/:id : id not found : #{params['id']}"
    raise Sinatra::NotFound
  end

  begin
    sec = JSON.parse(sec_json)
  rescue StandardError => e
    logger.error "GET /api/v1/secret/:id : JSON.parse failed : #{e.class} : #{e.message} : #{key} : #{sec_json}"
    raise Sinatra::NotFound
  ensure
    # Ensure we always delete found data immediately on
    # first view, no matter what happens with the parse.
    settings.redis.del(key)
    logger.info "GET /api/v1/secret/:id : deleted id : #{params['id']}"
  end

  # validate the outgoing data against the hash it was stored under to
  # ensure it has not been modified while at rest.
  unless valid_hash?(params['id'], [sec['scryptSaltB64'], sec['boxNonceB64'], sec['boxB64']])
    halt 500, error_json('Server error, stored data does not match its hash, discarding', 500)
  end

  return success_json(sec)
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
  halt 404, error_json('Not Found', 404)
end

# Custom error handler for sinatra-param
# https://github.com/mattt/sinatra-param
error Sinatra::Param::InvalidParameterError do
  halt 400, error_json("#{env['sinatra.error'].param} is invalid", 400)
end

error do
  logger.error 'unhandled error'
  halt 500, error_json('Server Error', 500)
end

# Integrity check helper. Ensure the content that will be
# stored, or that has been retrieved, matches exactly
# what was HMAC'ed on the client using BLAKE2s with
# a shared pepper and 16 Byte output.
def valid_hash?(client_hash, server_arr)
  b2_pepper = Blake2::Key.from_string('zerotime')
  server_hash = Blake2.hex(server_arr.join, b2_pepper, 16)
  # secure constant-time string comparison
  if RbNaCl::Util.verify32(server_hash, client_hash)
    return true
  else
    logger.warn "valid_hash? : false : #{client_hash} : #{server_hash}"
    return false
  end
end

# Capture basic aggregate statistics
def stats_increment(metric)
  raise 'invalid metric' unless metric.is_a?(String)
  t = Time.now.utc
  stats_base = 'zerotime:stats'
  total_key = "#{stats_base}:#{metric}"
  total_year_key = "#{total_key}:#{t.year}"
  total_month_key = "#{total_year_key}:#{t.month}"
  total_day_key = "#{total_month_key}:#{t.day}"
  total_hour_key = "#{total_day_key}:#{t.hour}"

  settings.redis.incr(total_key)
  settings.redis.incr(total_year_key)
  settings.redis.incr(total_month_key)
  settings.redis.incr(total_day_key)
  settings.redis.incr(total_hour_key)
end

def stat_total(metric)
  num = settings.redis.get("zerotime:stats:#{metric}")
  num.nil? ? 0 : num
end

def stat_year(metric)
  t = Time.now.utc
  num = settings.redis.get("zerotime:stats:#{metric}:#{t.year}")
  num.nil? ? 0 : num
end

def stat_month(metric)
  t = Time.now.utc
  num = settings.redis.get("zerotime:stats:#{metric}:#{t.year}:#{t.month}")
  num.nil? ? 0 : num
end

def stat_day(metric)
  t = Time.now.utc
  num = settings.redis.get("zerotime:stats:#{metric}:#{t.year}:#{t.month}:#{t.day}")
  num.nil? ? 0 : num
end

def stat_hour(metric)
  t = Time.now.utc
  num = settings.redis.get("zerotime:stats:#{metric}:#{t.year}:#{t.month}:#{t.day}:#{t.hour}")
  num.nil? ? 0 : num
end

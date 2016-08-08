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

helpers Sinatra::Param

# Common JSON response format
# http://labs.omniti.com/labs/jsend
# https://github.com/hetznerZA/jsender
include Jsender

configure do
  # Sinatra
  set :server, :puma
  set :root, "#{File.dirname(__FILE__)}/../"

  # Content Settings
  set :site_name, ENV['SITE_NAME'] ||= 'thesplit.is'
  set :site_domain, ENV['SITE_DOMAIN'] ||= 'thesplit.is'
  set :site_tagline, ENV['SITE_TAGLINE'] ||= 'the end-to-end encrypted, zero-knowledge, auto-expiring, cryptographically secure, secret sharing service'
  set :site_owner_name, ENV['SITE_OWNER_NAME'] ||= 'Glenn Rempe'
  set :site_owner_email, ENV['SITE_OWNER_EMAIL'] ||= 'glenn@rempe.us'
  set :site_owner_twitter, ENV['SITE_OWNER_TWITTER'] ||= 'grempe' # w/ no @ sign

  # Caching
  # https://www.sitepoint.com/sinatras-little-helpers/
  set :start_time, Time.now

  # App Specific Settings
  set :secrets_expire_in, 1.day
  set :secrets_max_length, 64.kilobytes
  set :base64_regex, %r{^[a-zA-Z0-9+=\/\-\_]+$}
  set :hex_regex, /^[a-f0-9]+$/

  # Sinatra CORS
  # https://github.com/britg/sinatra-cross_origin
  # http://www.html5rocks.com/en/tutorials/cors/
  set :cross_origin, true
  set :allow_origin, :any
  set :allow_methods, [:head, :get, :put, :post, :delete, :options]
  set :allow_credentials, false
  set :allow_headers, ['*', 'Content-Type', 'Accept', 'AUTHORIZATION', 'Cache-Control']
  set :max_age, 2.days
  set :expose_headers, ['Cache-Control', 'Content-Language', 'Content-Type', 'Expires', 'Last-Modified', 'Pragma']

  # Sinatra Param
  # https://github.com/mattt/sinatra-param
  set :raise_sinatra_param_exceptions, true
  disable :show_exceptions
  enable :raise_errors

  # Cache-Control for static pages
  set :static_cache_control, [:public, max_age: 30.days, s_maxage: 24.hours]

  # REDIS

  redis_uri = URI.parse(ENV['REDISCLOUD_URL'] ||= 'redis://127.0.0.1:6379')
  rparam = { host: redis_uri.host, port: redis_uri.port, password: redis_uri.password }

  redis_client = if settings.test?
                   MockRedis.new(rparam)
                 else
                   Redis.new(rparam)
                 end

  # Core Redis client for general use in the app.
  $redis = Redis::Namespace.new(:split, redis: redis_client)

  # If using Redistat in multiple threads set this
  # somewhere in the beginning of the execution stack
  Redistat.thread_safe = true
  Redistat.connection = Redis::Namespace.new(:redistat, redis: redis_client)

  # namespace Sidekiq
  Sidekiq.configure_client do |config|
    config.redis = { uri: redis_uri, namespace: 'sidekiq' }
  end

  # Content Security Policy (CSP)
  set :csp_enabled, true
  # CSP : If true, only report, don't actually enforce in the browser
  set :csp_report_only, false
end

configure :production, :development do
  enable :logging
end

before do
  # all responses are JSON by default
  content_type :json

  # Caching Dynamic Pages
  # see also Rack::CacheControlHeaders middleware
  # which prevents caching of /api/* and
  # :static_cache_control in config section for
  # static files.
  last_modified settings.start_time
  etag settings.start_time.to_s
  expires 1.hour, :public, s_maxage: 24.hours

  # Content Security Policy
  # https://content-security-policy.com
  if settings.csp_enabled?
    csp = []
    csp << "default-src 'none'"
    csp << "script-src 'self' 'unsafe-eval'"
    csp << "connect-src #{request.scheme}://#{request.host}:#{request.port}"
    csp << "img-src 'self'"
    csp << "style-src 'self' 'unsafe-inline'"
    csp << "frame-ancestors 'none'"
    csp << "form-action 'self'"
    csp << 'upgrade-insecure-requests'
    csp << 'block-all-mixed-content'
    csp << 'referrer no-referrer'
    csp << 'report-uri /csp'

    header = 'Content-Security-Policy'
    header += '-Report-Only' if settings.csp_report_only?
    response.headers[header] = csp.join(';')
  end
end

get '/' do
  Stats.store('views/root', count: 1)
  content_type :html
  erb :index
end

options '/' do
  response.headers['Allow'] = 'HEAD,GET'
  200
end

# Heartbeat endpoint for monitoring
get '/heartbeat' do
  expires 0, :no_cache, s_maxage: 0
  Stats.store('views/heartbeat', count: 1)
  return success_json(timestamp: Time.now.utc.iso8601)
end

options '/heartbeat' do
  response.headers['Allow'] = 'HEAD,GET'
  200
end

# Content Security Policy (CSP) Reports
post '/csp' do
  if params && params['csp-report'].present?
    if params['csp-report']['violated-directive'].present?
      directive = params['csp-report']['violated-directive'].strip.to_s
      Stats.store('csp', :count => 1, directive => 1)
    else
      Stats.store('csp', count: 1, unknown: 1)
    end
    logger.warn params['csp-report']
  end
  return success_json
end

options '/csp' do
  response.headers['Allow'] = 'POST'
  200
end


# Tierion Blockchain Subscription Callback
#
# Sample Payload
#
# {
#   "id"=>"57a6b24046f09ed12f13c2b6",
#   "merkleRoot"=>"59475c7ae20a4fadf106c8820fd36634123ca6d2c9a07fbfc1148cb850c12c93",
#   "transactionId"=>"609eb7df1bd56b67f7fed347c7696ce3aaa0bc0dc06b3ff3fb2fb6e22d00b1f0",
#   "startTimestamp"=>"2016-08-07T03:50:00.069Z",
#   "endTimestamp"=>"2016-08-07T04:00:00.043Z"
# }
#
post '/api/v1/blockchain_callback' do
  param :id, String, required: true, min_length: 24, max_length: 24,
                     format: settings.hex_regex

  param :merkleRoot, String, required: true, min_length: 64, max_length: 64,
                             format: settings.hex_regex

  param :transactionId, String, required: true, min_length: 64, max_length: 64,
                                format: settings.hex_regex

  param :startTimestamp, String, required: true
  param :endTimestamp, String, required: true

  BlockchainGetReceiptsWorker.perform_async

  return success_json
end

options '/api/v1/blockchain_callback' do
  response.headers['Allow'] = 'POST'
  200
end

post '/api/v1/secrets' do
  Stats.store('views/api/v1/secrets', count: 1, post: 1)

  # ID is 16 byte hash of the data that was stored
  param :id, String, required: true, min_length: 32, max_length: 32,
                     format: settings.hex_regex

  param :boxNonceB64, String, required: true, min_length: 24, max_length: 64,
                              format: settings.base64_regex

  param :boxB64, String, required: true, min_length: 1,
                         max_length: settings.secrets_max_length,
                         format: settings.base64_regex

  param :scryptSaltB64, String, required: true, min_length: 24, max_length: 64,
                                format: settings.base64_regex

  # Differentiate between the client_hash_id and the server_hash_id.
  # The client hash is the hash of the contents generated by the client
  # and used as the client ID for requesting a secret.
  #
  # The server_hash_id is just the SHA256(client_hash_id) and is what is
  # used on the server side to store and find secrets.
  #
  # This simple step is taken help prevent reversing of the server storeage
  # key back to its original client ID. This prevents an attacker who gains
  # control of a DB dump from being able to search for that ID globally
  # (e.g. searching all email, or all Twitter, etc.) in order to
  # learn something about who has held that key ID. A small step
  # towards protecting the anonymity of the creator.
  #
  client_hash_id  = params['id']
  server_hash_id  = Digest::SHA256.hexdigest(client_hash_id)

  scrypt_salt_b64 = params['scryptSaltB64']
  box_nonce_b64   = params['boxNonceB64']
  box_b64         = params['boxB64']

  t     = Time.now
  t_exp = t + settings.secrets_expire_in
  key   = secret_storage_redis_key(server_hash_id)

  unless $redis.get(key).blank?
    halt 409, error_json('Data conflict, secret with ID already exists', 409)
  end

  obj = { boxNonceB64: box_nonce_b64,
          boxB64: box_b64,
          scryptSaltB64: scrypt_salt_b64 }

  $redis.set(key, obj.to_json)
  $redis.expire(key, settings.secrets_expire_in)

  # Generate a hash of the entire object stored in the DB for this secret
  # and send it to the blockchain for storage. Send the server_hash_id as
  # well to allow later lookup and random verification that what is stored
  # in a record is still what is there and recorded on the blockchain.
  BlockchainSendHashWorker.perform_async(server_hash_id, ObjectHash.hexdigest(obj))

  return success_json(id: client_hash_id, createdAt: t.utc.iso8601,
                      expiresAt: t_exp.utc.iso8601)
end

options '/api/v1/secrets' do
  response.headers['Allow'] = 'POST'
  200
end

delete '/api/v1/secrets/:id' do
  Stats.store('views/api/v1/secrets/id', count: 1)

  # ID is 16 byte hash of the data that was stored
  param :id, String, required: true, min_length: 32, max_length: 32,
                     format: settings.hex_regex

  client_hash_id = params['id']
  key = secret_storage_redis_key(Digest::SHA256.hexdigest(client_hash_id))
  $redis.del(key)

  return success_json
end

get '/api/v1/secrets/:id' do
  Stats.store('views/api/v1/secrets/id', count: 1)

  # ID is the 16 byte hash of the data that was stored
  param :id, String, required: true, min_length: 32, max_length: 32,
                     format: settings.hex_regex

  client_hash_id = params['id']
  key = secret_storage_redis_key(Digest::SHA256.hexdigest(client_hash_id))
  sec_json = $redis.get(key)

  raise Sinatra::NotFound if sec_json.blank?

  begin
    sec = JSON.parse(sec_json)
  rescue StandardError
    halt 500, error_json('Fatal error, corrupt data, JSON', 500)
  ensure
    # Always delete found data immediately on first view,
    # even if the parse fails.
    $redis.del(key)
  end

  return success_json(sec)
end

options '/api/v1/secrets/:id' do
  response.headers['Allow'] = 'GET,DELETE'
  200
end

# Sinatra::NotFound handler
not_found do
  Stats.store('views/error/404', count: 1)
  halt 404, error_json('Not Found', 404)
end

# Custom error handler for sinatra-param
# https://github.com/mattt/sinatra-param
error Sinatra::Param::InvalidParameterError do
  # Also store the name of the invalid param in the stats db
  Stats.store('views/error/400', 'count' => 1, env['sinatra.error'].param => 1)
  halt 400, error_json("#{env['sinatra.error'].param} is invalid", 400)
end

error do
  Stats.store('views/error/500', count: 1)
  halt 500, error_json('Server Error', 500)
end

def secret_storage_redis_key(id)
  "secrets:#{id}"
end

helpers Sinatra::Param

# Common JSON response format
# http://labs.omniti.com/labs/jsend
# https://github.com/hetznerZA/jsender
include Jsender

configure do
  # Sinatra
  set :server, :puma
  set :root, "#{File.dirname(__FILE__)}/../"
  # set :views, "#{settings.root}/../views"

  # Caching
  # https://www.sitepoint.com/sinatras-little-helpers/
  set :start_time, Time.now

  # App Specific Settings
  set :secrets_expire_in, 1.day
  set :secrets_max_length, 64.kilobytes
  set :base64_regex, /^[a-zA-Z0-9+=\/\-\_]+$/
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

  # Redis
  set :redis, Redis.new(url: ENV['REDIS_URL'] ||= 'redis://127.0.0.1:6379')

  # Redistat
  # If using Redistat in multiple threads set this
  # somewhere in the beginning of the execution stack
  Redistat.thread_safe = true

  Redistat.connect(host: settings.redis.client.host,
                   port: settings.redis.client.port,
                   db: settings.redis.client.db)

  # Content Security Policy (CSP)
  set :csp_enabled, true
  # CSP : Only report, don't actually enforce in the browser
  set :csp_report_only, true
end

configure :production, :development do
  enable :logging
end

before do
  # all responses are JSON by default
  content_type :json

  # Caching
  # see also Rack::CacheControlHeaders middleware
  # which prevents caching of /api/*
  last_modified settings.start_time
  etag settings.start_time.to_s
  expires 1.hour, :public, :must_revalidate

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
  Stats.store('views/heartbeat', count: 1)
  return success_json(timestamp: Time.now.utc.iso8601)
end

# Content Security Policy (CSP) Reports
post '/csp' do
  if params && params['csp-report'].present?
    if params['csp-report']['violated-directive'].present?
      Stats.store('csp', :count => 1, params['csp-report']['violated-directive'].strip.to_s => 1)
    else
      Stats.store('csp', count: 1, unknown: 1)
    end
    logger.warn params['csp-report']
  end
  return success_json
end

post '/api/v1/secrets' do
  Stats.store('views/api/v1/secrets', count: 1, post: 1)

  param :blake2sHash, String, required: true, min_length: 32, max_length: 32,
                              format: settings.hex_regex

  param :boxNonceB64, String, required: true, min_length: 24, max_length: 64,
                              format: settings.base64_regex

  param :boxB64, String, required: true, min_length: 1,
                         max_length: settings.secrets_max_length, format: settings.base64_regex

  param :scryptSaltB64, String, required: true, min_length: 24, max_length: 64,
                                format: settings.base64_regex

  blake2s_hash    = params['blake2sHash']
  scrypt_salt_b64 = params['scryptSaltB64']
  box_nonce_b64   = params['boxNonceB64']
  box_b64         = params['boxB64']

  unless valid_hash?(blake2s_hash, [scrypt_salt_b64, box_nonce_b64, box_b64])
    halt 400, error_json('Integrity hash mismatch', 400)
  end

  t     = Time.now
  t_exp = t + settings.secrets_expire_in
  key   = "secrets:#{blake2s_hash}"

  unless settings.redis.get(key).blank?
    halt 409, error_json('Data conflict, secret with ID already exists', 409)
  end

  settings.redis.set(key, { boxNonceB64: box_nonce_b64,
                            boxB64: box_b64,
                            scryptSaltB64: scrypt_salt_b64 }.to_json)

  settings.redis.expire(key, settings.secrets_expire_in)

  return success_json(id: blake2s_hash, createdAt: t.utc.iso8601,
                      expiresAt: t_exp.utc.iso8601)
end

options '/api/v1/secrets' do
  response.headers['Allow'] = 'POST'
  200
end

delete '/api/v1/secrets/:id' do
  Stats.store('views/api/v1/secrets/id', count: 1)

  # id is 16 byte BLAKE2s hash of the data that was stored
  param :id, String, required: true, min_length: 32, max_length: 32,
                     format: settings.hex_regex

  key = "secrets:#{params['id']}"
  settings.redis.del(key)

  return success_json
end

get '/api/v1/secrets/:id' do
  Stats.store('views/api/v1/secrets/id', count: 1)

  # id is 16 byte BLAKE2s hash of the data that was stored
  param :id, String, required: true, min_length: 32, max_length: 32,
                     format: settings.hex_regex

  key = "secrets:#{params['id']}"
  sec_json = settings.redis.get(key)

  raise Sinatra::NotFound if sec_json.blank?

  begin
    sec = JSON.parse(sec_json)
  rescue StandardError
    halt 500, error_json('Fatal error, corrupt data, JSON', 500)
  ensure
    # Always delete found data immediately on
    # first view, even if the parse fails.
    settings.redis.del(key)
  end

  # validate the outgoing data against the hash it was stored under to
  # ensure it has not been modified while at rest.
  unless valid_hash?(params['id'], [sec['scryptSaltB64'], sec['boxNonceB64'], sec['boxB64']])
    halt 500, error_json('Fatal error, corrupt data, HMAC', 500)
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
  Stats.store('views/error/400', {'count' => 1, env['sinatra.error'].param => 1})
  halt 400, error_json("#{env['sinatra.error'].param} is invalid", 400)
end

error do
  Stats.store('views/error/500', count: 1)
  halt 500, error_json('Server Error', 500)
end

# Integrity check. Ensure the content that will be
# stored, or that has been retrieved, matches exactly
# what was HMAC'ed on the client using BLAKE2s with
# a shared pepper and 16 Byte output. Compare HMAC
# using secure constant-time string comparison.
def valid_hash?(client_hash, server_arr)
  b2_pepper = Blake2::Key.from_string('secret:app:pepper')
  server_hash = Blake2.hex(server_arr.join, b2_pepper, 16)
  RbNaCl::Util.verify32(server_hash, client_hash) ? true : false
end

require './config/boot'

#################################################
# Middleware - Compress Responses
#################################################

# http://rack.rubyforge.org/doc/Rack/Deflater.html
# Automatically disabled if 'no-transform'
# Cache-Control response is set in the headers

# To test this is working you need to use the
# right curl invocation:
# curl -i --head "Accept-Encoding: gzip,deflate" http://localhost:3000

# Only if body size is large enough
# See : http://perlkour.pl/2015/09/rack-deflater-in-sinatra/
use Rack::Deflater, :if => lambda {
  |env, status, headers, body| body.length > 512
}

#################################################
# Middleware - Rack::Robustness (Outer Layer)
#################################################

##
# Catches all errors.
#
# Respond as specified.
#
use Rack::Robustness do |g|
  g.status 500
  g.content_type 'application/json'
  g.body({status: 'error', message: 'server error', code: 500}.to_json)
end

#################################################
# Middleware - Rack::Attack - Rate Limiting
#################################################

use Rack::Attack

redis_url = ENV.fetch('REDIS_URL') { 'redis://127.0.0.1:6379' }
Rack::Attack.cache.store = ActiveSupport::Cache::RedisStore.new(redis_url)

Rack::Attack.throttle('sidekiq/req/ip', limit: 180, period: 1.minute) do |req|
  req.ip if req.path.start_with?('/sidekiq')
end

Rack::Attack.throttle('static/req/ip', limit: 180, period: 1.minute) do |req|
  req.ip if req.path.start_with?('/css', '/js', '/favicon.ico', '/humans.txt', '/robots.txt')
end

Rack::Attack.throttle('api/req/ip', limit: 180, period: 1.minute) do |req|
  req.ip if req.path.start_with?('/api')
end

Rack::Attack.throttle('heartbeat/req/ip', limit: 10, period: 1.minute) do |req|
  req.ip if req.path.start_with?('/heartbeat')
end

Rack::Attack.throttle('blockchain/req/ip', limit: 10, period: 1.minute) do |req|
  req.ip if req.path.start_with?('/blockchain_callback')
end

Rack::Attack.throttled_response = lambda do |env|
  now = Time.now
  match_data = env['rack.attack.match_data']

  headers = {
    'X-RateLimit-Limit' => match_data[:limit].to_s,
    'X-RateLimit-Remaining' => '0',
    'X-RateLimit-Reset' => (now + (match_data[:period] - now.to_i % match_data[:period])).to_s
  }

  [ 429, headers, ["Throttled\n"]]
end

#################################################
# Middleware - Rack::Cors
#################################################

# TESTING :
#
# See:
#   http://stackoverflow.com/questions/12173990/how-can-you-debug-a-cors-request-with-curl#12179364
#
# Simple Example:
#
#   curl -H "Origin:*" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: X-Requested-With" -X OPTIONS --verbose http://localhost:3000/heartbeat
#   curl -H "Origin:*" -H "Access-Control-Request-Method: GET" -H "Access-Control-Request-Headers: X-Requested-With" -H $TOKEN -X OPTIONS --verbose http://localhost:3000/heartbeat
#
cors_debug = ENV.fetch('RACK_ENV') == 'production' ? false : true
use Rack::Cors, debug: cors_debug do
  allow do
    origins '*'
    resource '/heartbeat', max_age: 3600, headers: :any, methods: [:get]
    resource '/sidekiq', max_age: 3600, headers: :any, methods: [:get, :post]
    resource '/blockchain_callback', max_age: 3600, headers: :any, methods: [:post]
    resource '/api/v1/users', max_age: 3600, headers: :any, methods: [:post]
    resource '/api/v1/users/*', max_age: 3600, headers: :any, methods: [:get]
    resource '/api/v1/users/*/srp/challenge', max_age: 3600, headers: :any, methods: [:post]
    resource '/api/v1/users/*/srp/authenticate', max_age: 3600, headers: :any, methods: [:post]
    resource '/api/v1/secrets', max_age: 3600, headers: :any, methods: [:get, :post]
    resource '/api/v1/secrets/*', max_age: 3600, headers: :any, methods: [:get, :delete]
    resource '/api/v1/secrets/*/receipt', max_age: 3600, headers: :any, methods: [:get]
    resource '/', max_age: 3600, headers: :any, methods: [:get]
  end
end


#################################################
# Middleware - Rack::CacheControlHeaders
#################################################

# A custom middleware.

# See : https://www.mobify.com/blog/beginners-guide-to-http-cache-headers/
# See : https://github.com/mintdigital/rack-access-control-headers/blob/master/lib/rack/access-control-headers.rb
# See : http://railscasts.com/episodes/151-rack-middleware

module Rack
  class CacheControlHeaders
    def initialize(app, path)
      @app = app
      @path = path
    end

    def call(env)
      dup._call(env)
    end

    def _call(env)
      response = @app.call(env)
      if env['PATH_INFO'].match @path
        response[1]['Cache-Control'] = 'private, max-age=0, s-maxage=0, no-cache, no-store, must-revalidate, proxy-revalidate'
        response[1]['Expires'] = Time.now.httpdate
        response[1]['Pragma'] = 'no-cache'
      end
      response
    end
  end
end

# Set strict no-cache headers for these endpoints
use Rack::CacheControlHeaders, '/sidekiq'
use Rack::CacheControlHeaders, '/heartbeat'
use Rack::CacheControlHeaders, '/blockchain_callback'
use Rack::CacheControlHeaders, '/api'

#################################################
# Middleware - Accept and Parse Form or JSON
#################################################

use ::Rack::NestedParams
use ::Rack::PostBodyContentTypeParser


#################################################
# Middleware - Rollbar Exception Logging
#################################################
require 'rollbar/middleware/sinatra'
use Rollbar::Middleware::Sinatra

#################################################
# Routes
#################################################

# Sidekiq Admin UI (Basic Auth)
# Access via (note trailing slash):
#   http://0.0.0.0:3000/sidekiq/
Sidekiq::Web.use Rack::Auth::Basic do |username, password|
  username == ENV.fetch('SIDEKIQ_USERNAME') && password == ENV.fetch('SIDEKIQ_PASSWORD')
end if ENV.fetch('RACK_ENV') == 'production'

map('/sidekiq') { run Sidekiq::Web }
map('/heartbeat') { run HeartbeatController }
map('/blockchain_callback') { run BlockchainCallbackController }
map('/api/v1/users') { run UsersController }
map('/api/v1/secrets') { run SecretsController }
map('/') { run ApplicationController }

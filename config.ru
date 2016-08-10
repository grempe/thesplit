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

redis_url = ENV['REDIS_URL'] ||= 'redis://127.0.0.1:6379'
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

Rack::Attack.throttle('csp/req/ip', limit: 10, period: 1.minute) do |req|
  req.ip if req.path.start_with?('/csp')
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
use Rack::CacheControlHeaders, '/csp'
use Rack::CacheControlHeaders, '/blockchain_callback'
use Rack::CacheControlHeaders, '/api'

#################################################
# Middleware - Accept and Parse Form or JSON
#################################################

use ::Rack::NestedParams
use ::Rack::PostBodyContentTypeParser

#################################################
# Routes
#################################################

# Sidekiq Admin UI (Basic Auth)
Sidekiq::Web.use Rack::Auth::Basic do |username, password|
  username == ENV['SIDEKIQ_USERNAME'] && password == ENV['SIDEKIQ_PASSWORD']
end if ENV['RACK_ENV'] == 'production'
map('/sidekiq') { run Sidekiq::Web }

map('/heartbeat') { run HeartbeatController }
map('/csp') { run ContentSecurityPolicyController }
map('/blockchain_callback') { run BlockchainCallbackController }
map('/api/v1/secrets') { run SecretsController }
map('/') { run ApplicationController }

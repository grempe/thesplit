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

require 'rubygems'
require 'bundler/setup'

Bundler.require(:default)
Bundler.require(Sinatra::Base.environment)

require 'active_support/cache/redis_store'
require 'active_support/core_ext/object/blank'
require 'active_support/core_ext/numeric'
require 'active_support/core_ext/integer/time'

require 'sidekiq/api'

Dir[File.expand_path('../../app/*.rb', __FILE__)].each do |file| load file; end
Dir[File.expand_path('../../app/workers/*.rb', __FILE__)].each do |file| load file; end

#################################################
# Middleware - Compress Responses
#################################################

# http://rack.rubyforge.org/doc/Rack/Deflater.html
# Automatically disabled if 'no-transform'
# Cache-Control response is set in the headers

use Rack::Deflater

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
  g.body(error_json('server error', 500))
end

#################################################
# Middleware - Rack::Attack - Rate Limiting
#################################################

class Rack::Attack
  # LEARN MORE
  #
  # Rack::Attack
  # See : https://github.com/kickstarter/rack-attack
  # See : https://github.com/kickstarter/rack-attack/issues/102
  # See : https://gist.github.com/ktheory/5087320

  # Configure Cache
  #
  # Note: The store is only used for throttling (not blacklisting and
  # whitelisting). It must implement .increment and .write like
  # ActiveSupport::Cache::Store
  redis_url = ENV['REDIS_URL'] ||= 'redis://127.0.0.1:6379'
  Rack::Attack.cache.store = ActiveSupport::Cache::RedisStore.new(redis_url)

  # Whitelist all requests from localhost
  # (blacklist & throttles are skipped)
  #
  # if ENV['RACK_ENV'] == 'production'
  #   whitelist('allow from localhost') do |req|
  #    '127.0.0.1' == req.ip || '::1' == req.ip
  #   end
  # end

  # Block requests from 1.2.3.4
  # Rack::Attack.blacklist('block 1.2.3.4') do |req|
  #   # Requests are blocked if the return value is truthy
  #   '1.2.3.4' == req.ip
  # end

  # Block logins from a bad user agent
  # Rack::Attack.blacklist('block bad UA logins') do |req|
  #   req.path == '/login' && req.post? && req.user_agent == 'BadUA'
  # end

  # Throttle all static asset requests by IP (100rpm)
  #
  # Key: "rack::attack:#{Time.now.to_i/:period}:static/req/ip:#{req.ip}"
  throttle('static/req/ip', limit: 100, period: 1.minute) do |req|
    req.ip if req.path.start_with?('/index.html', '/dist')
  end

  # Throttle all /api requests by IP (100rpm)
  #
  # Key: "rack::attack:#{Time.now.to_i/:period}:api/req/ip:#{req.ip}"
  throttle('api/req/ip', limit: 100, period: 1.minute) do |req|
    req.ip if req.path.start_with?('/api/v1')
  end
end

# By running only in prod no local redis is needed in dev/test
if ENV['RACK_ENV'] == 'production'
  use Rack::Attack
end

#################################################
# Middleware - Rack::Attack::RateLimit - Headers
#################################################

# See : https://github.com/jbyck/rack-attack-rate-limit
# Takes an array of names of Rack::Attack.throttle instances
# Places header like the following in all non-throttled requests:
#
#   X-Ratelimit-Limit: 10
#   X-Ratelimit-Remaining: 8

# By running only in prod no local redis is needed in dev/test
if ENV['RACK_ENV'] == 'production'
  use Rack::Attack::RateLimit, throttle: ['static/req/ip', 'api/req/ip']
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
        response[1]['Cache-Control'] = 'private, max-age=0, s-maxage=0, no-cache, no-store, must-revalidate, no-transform, proxy-revalidate'
        response[1]['Expires'] = Time.now.httpdate
        response[1]['Pragma'] = 'no-cache'
      end
      response
    end
  end
end

# Set strict no-cache headers for all /api/* calls
use Rack::CacheControlHeaders, '/api'

#################################################
# Middleware - Accept and Parse Form or JSON
#################################################

use Rack::NestedParams
use Rack::PostBodyContentTypeParser

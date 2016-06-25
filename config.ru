require 'rack'
require 'rack/contrib'
require 'redis'
require './zerotime'

# http://edgeguides.rubyonrails.org/active_support_core_extensions.html#time
require 'active_support'
require 'active_support/core_ext/object/blank.rb'
require 'active_support/core_ext/numeric'
require 'active_support/cache/redis_store'
require 'active_support/core_ext/string/starts_ends_with.rb'
require 'active_support/core_ext/object/try.rb'

#################################################
# Middleware - Rack::Profiler - Performance
#################################################

# Add ?profile=process_time query string param to a URL
# in the browser to generate a details performance report.
use Rack::Profiler if ENV['RACK_ENV'] == 'development'

#################################################
# Middleware - Rack::Attack - Rate Limiting
#################################################

require 'rack/attack'
require 'rack/attack/rate-limit'

REDIS_URL = ENV['REDIS_URL'] ||= 'redis://127.0.0.1:6379'

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

  Rack::Attack.cache.store = ActiveSupport::Cache::RedisStore.new(REDIS_URL)

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

use Rack::Attack

#################################################
# Middleware - Rack::Attack::RateLimit - Headers
#################################################

# See : https://github.com/jbyck/rack-attack-rate-limit
# Takes an array of names of Rack::Attack.throttle instances
# Places header like the following in all non-throttled requests:
#
#   X-Ratelimit-Limit: 10
#   X-Ratelimit-Remaining: 8

use Rack::Attack::RateLimit, throttle: ['static/req/ip', 'api/req/ip']

#################################################
# Middleware - Accept and Parse Form or JSON
#################################################

use Rack::NestedParams
use Rack::PostBodyContentTypeParser

#################################################
# Sinatra - START
#################################################

run Sinatra::Application

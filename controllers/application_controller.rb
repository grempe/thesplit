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

class ApplicationController < Sinatra::Base
  # Common JSON response format
  # http://labs.omniti.com/labs/jsend
  # https://github.com/hetznerZA/jsender
  include Jsender

  #################################################
  # Helpers
  #################################################

  helpers ApplicationHelper
  helpers Sinatra::Param

  #################################################
  # Extensions
  #################################################

  register Sinatra::CrossOrigin

  #################################################
  # Config Settings
  #################################################

  # set folder for templates to ../views, but make the path absolute
  set :views, File.expand_path('../../views', __FILE__)

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

    redis_uri = URI.parse(ENV['REDIS_URL'] ||= 'redis://127.0.0.1:6379')
    rparam = { host: redis_uri.host, port: redis_uri.port, password: redis_uri.password }

    redis_client = if settings.test?
                     MockRedis.new(rparam)
                   else
                     Redis.new(rparam)
                   end

    # Core Redis client for general use in the app.
    $redis = redis_client

    # If using Redistat in multiple threads set this
    # somewhere in the beginning of the execution stack
    Redistat.thread_safe = true
    Redistat.connection = Redis::Namespace.new(:redistat, redis: redis_client)

    # namespace Sidekiq
    Sidekiq.configure_client do |config|
      config.redis = { namespace: 'sidekiq' }
    end

    Sidekiq.configure_server do |config|
      config.redis = { namespace: 'sidekiq' }
    end

    # Content Security Policy (CSP)
    set :csp_enabled, true
    # CSP : If true, only report, don't actually enforce in the browser
    set :csp_report_only, false
  end

  configure :production, :development do
    enable :logging
  end

  #################################################
  # Before - apply to all requests
  #################################################

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

    # Add headers for all unthrottled requests also
    # See Rack::Attack in config.ru
    if request.env['rack.attack.throttle_data'].present?
      now = Time.now
      key = request.env['rack.attack.throttle_data'].keys.first
      throttle_data = request.env['rack.attack.throttle_data'][key]
      response.headers['X-RateLimit-Limit'] = throttle_data[:limit].to_s
      response.headers['X-RateLimit-Remaining'] = (throttle_data[:limit].to_i - throttle_data[:count].to_i).to_s
      response.headers['X-RateLimit-Reset'] = (now + (throttle_data[:period] - now.to_i % throttle_data[:period])).to_s
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
end

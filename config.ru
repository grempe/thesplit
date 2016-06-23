require 'rack'
require 'rack/contrib'
require './zerotime'

# Add ?profile=process_time query string param to a URL
# in the browser to generate a details performance report.
use Rack::Profiler if ENV['RACK_ENV'] == 'development'
use Rack::NestedParams
use Rack::PostBodyContentTypeParser

run Sinatra::Application

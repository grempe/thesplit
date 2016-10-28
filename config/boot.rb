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

# Load Dotenv as early in the boot process as possible
# Top-most files override lower files
# See : http://www.virtuouscode.com/2014/01/17/dotenv-for-multiple-environments/
# See : https://juanitofatas.com/blog/2016/08/28/manage_your_project_s_environment_variables
require 'dotenv'
env = ENV.fetch('RACK_ENV') { 'development' }
Dotenv.load(
  File.expand_path('../../.env.local', __FILE__),
  File.expand_path("../../.env.#{env}", __FILE__),
  File.expand_path('../../.env', __FILE__)
)

require 'sidekiq/api'
require 'sidekiq/web'
require 'sidekiq-scheduler/web'

require './helpers/application_helper'
require './controllers/application_controller'

Dir.glob('./{helpers,controllers,models,workers}/*.rb').each do |file|
  require file
end

Rollbar.configure do |config|
  config.access_token = ENV.fetch('ROLLBAR_ACCESS_TOKEN')
  config.disable_monkey_patch = true
  config.use_sidekiq 'queue' => 'default'
  config.exception_level_filters.merge!({
    'Sinatra::NotFound' => 'ignore'
  })
end

# Security : scrub additional fields from Rollbar logs
Rollbar.configuration.scrub_fields |= [:boxNonceB64, :boxB64, :scryptSaltB64]

Vault.configure do |config|
  # The address of the Vault server, also read as ENV["VAULT_ADDR"]
  config.address = ENV.fetch('VAULT_ADDR')

  # The token to authenticate with Vault, also read as ENV["VAULT_TOKEN"]
  config.token = ENV.fetch('VAULT_TOKEN')

  # Proxy connection information, also read as ENV["VAULT_PROXY_(thing)"]
  # config.proxy_address  = "..."
  # config.proxy_port     = "..."
  # config.proxy_username = "..."
  # config.proxy_password = "..."

  # Custom SSL PEM, also read as ENV["VAULT_SSL_CERT"]
  # config.ssl_pem_file = "/path/on/disk.pem"

  # Use SSL verification, also read as ENV["VAULT_SSL_VERIFY"]
  config.ssl_verify = ENV.fetch('VAULT_SSL_VERIFY') { false }

  # Timeout the connection after a certain amount of time (seconds), also read
  # as ENV["VAULT_TIMEOUT"]
  config.timeout = ENV.fetch('VAULT_TIMEOUT') { 30 }

  # It is also possible to have finer-grained controls over the timeouts, these
  # may also be read as environment variables
  # config.ssl_timeout  = 5
  # config.open_timeout = 5
  # config.read_timeout = 30
end

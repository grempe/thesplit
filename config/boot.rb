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
require 'sidekiq/web'
require 'sidekiq-scheduler/web'

require './helpers/application_helper'
require './controllers/application_controller'

Dir.glob('./{helpers,controllers,models,workers}/*.rb').each do |file|
  require file
end

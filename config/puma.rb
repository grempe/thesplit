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

if ENV['RACK_ENV'] == 'production'
  workers Integer(ENV.fetch('PUMA_WORKERS') { 1 })
  threads_count = Integer(ENV.fetch('PUMA_THREADS') { 5 })
else
  workers 1
  threads_count = 1
end

threads threads_count, threads_count

preload_app!

rackup      DefaultRackup
port        ENV.fetch('PORT') { 3000 }
environment ENV.fetch('RACK_ENV') { 'development' }

on_worker_boot do
  # Do Something Here
end

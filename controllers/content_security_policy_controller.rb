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

# Endpoint for browser Content Security Policy (CSP) Reports
class ContentSecurityPolicyController < ApplicationController
  post '/' do
    if params && params['csp-report'].present?
      if params['csp-report']['violated-directive'].present?
        directive = params['csp-report']['violated-directive'].strip.to_s
      end
      logger.warn params['csp-report']
    end
    return success_json
  end

  options '/' do
    response.headers['Allow'] = 'POST'
    200
  end
end

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

require 'spec_helper'

RSpec.describe ApplicationController do
  describe 'GET /' do
    it 'returns 200' do
      get '/'
      expect(last_response.status).to eq 200
    end

    it 'has content type text/html' do
      get '/'
      expect(last_response.headers['Content-Type']).to eq('text/html;charset=utf-8')
    end

    it 'has expected body' do
      get '/'
      expect(last_response.body).to match(/thesplit.is/)
    end
  end
end

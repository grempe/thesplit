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

RSpec.describe BlockchainCallbackController do
  let(:payload) do
    {
      id: '57a6b24046f09ed12f13c2b6',
      merkleRoot: '59475c7ae20a4fadf106c8820fd36634123ca6d2c9a07fbfc1148cb850c12c93',
      transactionId: '609eb7df1bd56b67f7fed347c7696ce3aaa0bc0dc06b3ff3fb2fb6e22d00b1f0',
      startTimestamp: '2016-08-07T03:50:00.069Z',
      endTimestamp: '2016-08-07T04:00:00.043Z'
    }
  end

  describe 'POST /blockchain_callback' do
    context 'with valid params' do
      it 'returns 200' do
        post '/', payload
        expect(last_response.status).to eq 200
      end

      it 'has proper content type' do
        post '/', payload
        expect(last_response.headers['Content-Type']).to eq('application/json')
      end

      it 'has expected response' do
        post '/', payload
        expect(json_last_response['status']).to eq('success')
        expect(json_last_response['data']).to eq(nil)
      end
    end

    context 'with unknown param' do
      it 'returns 200' do
        post '/', payload.merge!(foo: 'bar')
        expect(last_response.status).to eq 200
      end
    end

    context 'with missing param' do
      context 'id' do
        it 'returns 400' do
          post '/', payload.delete(:id)
          expect(last_response.status).to eq 400
        end
      end

      context 'merkleRoot' do
        it 'returns 400' do
          post '/', payload.delete(:merkleRoot)
          expect(last_response.status).to eq 400
        end
      end

      context 'transactionId' do
        it 'returns 400' do
          post '/', payload.delete(:transactionId)
          expect(last_response.status).to eq 400
        end
      end

      context 'startTimestamp' do
        it 'returns 400' do
          post '/', payload.delete(:startTimestamp)
          expect(last_response.status).to eq 400
        end
      end

      context 'endTimestamp' do
        it 'returns 400' do
          post '/', payload.delete(:endTimestamp)
          expect(last_response.status).to eq 400
        end
      end
    end

  end
end

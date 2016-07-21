require 'spec_helper'

describe 'Secrets' do

  def app
    Sinatra::Application
  end

  before do
    app.settings.redis.flushdb
  end

  context 'GET /' do
    it 'returns expected result' do
      get '/'

      expect(last_response.headers['Content-Type']).to eq('text/html;charset=utf-8')
      expect(last_response.body).to match(/No humans allowed./)
      expect(last_response.status).to eq 200
    end
  end

  context 'OPTIONS /' do
    it 'returns expected result' do
      options '/'

      expect(last_response.headers['Allow']).to eq('HEAD,GET')
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Length']).to eq('0')
      expect(last_response.body).to eq('')
      expect(last_response.status).to eq 200
    end
  end
end

require 'sinatra'

get '/' do
  erb :index
end

post '/secret' do
end

get '/secret/:id' do
end

source 'https://rubygems.org'
ruby '2.2.5'

# current heroku supported version
gem 'bundler', '1.11.2'

gem 'json', '~> 2.0'
gem 'puma', '~> 3.5'
gem 'rack', '~> 1.6'
gem 'rack-contrib', '~> 1.4', require: 'rack/contrib'
gem 'rack-attack', '~> 4.4', require: 'rack/attack'
gem 'rack-attack-rate-limit', '~> 1.1', require: 'rack/attack/rate-limit'
gem 'rack-robustness', '~> 1.1', require: 'rack/robustness'
gem 'sinatra', '~> 1.4'
gem 'sinatra-param', '~> 1.4', require: 'sinatra/param'
gem 'sinatra-cross_origin', '~> 0.3', require: 'sinatra/cross_origin'

gem 'activesupport', '~> 5.0'
gem 'redis', '~> 3.3'
gem 'redis-activesupport', '~> 5.0'
gem 'redistat', git: 'https://github.com/grempe/redistat.git'

gem 'blake2', '~> 0.5'
gem 'rbnacl-libsodium', '~> 1.0', require: 'rbnacl/libsodium'
gem 'rbnacl', '~> 3.4', require: 'rbnacl'
gem 'jsender', '~> 0.2'

group :test, :development do
  gem 'rake'
  gem 'rspec'
  gem 'rack-test'
  gem 'pry'
  gem 'guard-puma'
end

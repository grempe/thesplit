source 'https://rubygems.org'
ruby '2.2.5'

# current heroku supported version
gem 'bundler', '1.11.2'

# replace SecureRandom
gem 'sysrandom', '~> 1.0', require: 'sysrandom/securerandom'

gem 'json', '~> 2.0'
gem 'puma', '~> 3.5'
gem 'rack', '~> 1.6'
gem 'rack-contrib', '~> 1.4', require: 'rack/contrib'
gem 'rack-attack', '~> 5.0', require: 'rack/attack'
gem 'rack-robustness', '~> 1.1', require: 'rack/robustness'
gem 'sinatra', '~> 1.4', require: 'sinatra/base'
gem 'sinatra-param', '~> 1.4', require: 'sinatra/param'
gem 'sinatra-cross_origin', '~> 0.3', require: 'sinatra/cross_origin'

gem 'activesupport', '~> 5.0'
gem 'redis', '~> 3.3'
gem 'redis-namespace', '~> 1.5'
gem 'redis-activesupport', '~> 5.0'
gem 'redistat', git: 'https://github.com/grempe/redistat.git'
gem 'sidekiq', '~> 4.1'
gem 'sidekiq-scheduler', '~> 2.0'
gem 'jsender', '~> 0.2'
gem 'objecthash', '~> 1.0', '>= 1.0.2'
gem 'tierion', '~> 1.3'

group :test, :development do
  gem 'rake'
  gem 'rspec'
  gem 'rack-test'
  gem 'pry'
  gem 'guard-puma'
  gem 'guard-rspec', require: false
  gem 'wwtd'
  gem 'mock_redis'
end

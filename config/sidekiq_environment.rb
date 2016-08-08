# This is an environment file that is to be used when loading the
# Sidekiq Asynch job queue. It loads only what the workers need.
require 'json'
require 'redis'
require 'redis-namespace'
require 'sidekiq'
require 'sidekiq-scheduler'
require 'tierion'

Dir[File.expand_path('../../app/workers/*.rb', __FILE__)].each do |file|
  load file
end

redis_uri = URI.parse(ENV['REDISCLOUD_URL'] ||= 'redis://127.0.0.1:6379')
$redis = Redis.new(uri: redis_uri)

if $redis.blank?
  raise 'Exiting. The $redis client is nil.'
end

if ENV['TIERION_ENABLED'] && ENV['TIERION_USERNAME'].present? && ENV['TIERION_PASSWORD'].present?
  $blockchain = Tierion::HashApi::Client.new()
end

if ENV['TIERION_ENABLED'] && $blockchain.blank?
  raise 'Exiting. TIERION_ENABLED is true, but $blockchain is nil. Bad auth?'
end

Sidekiq.configure_server do |config|
  config.redis = { uri: redis_uri, namespace: 'sidekiq' }
  config.on(:startup) do
    schedule = YAML.load_file(File.expand_path('../../config/sidekiq_scheduler.yml', __FILE__))
    Sidekiq.schedule = schedule
    Sidekiq::Scheduler.dynamic = true
    Sidekiq::Scheduler.reload_schedule!
  end
end

# Register a callback URL for Tierion (optional)
if ENV['TIERION_ENABLED'] && ENV['RACK_ENV'] == 'production'
  callback_uri = ENV['TIERION_SUBSCRIPTION_CALLBACK_URI']
  $blockchain.create_block_subscription(callback_uri) if callback_uri.present?
end

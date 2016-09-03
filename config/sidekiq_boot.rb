# This is an environment file that is to be used when loading the
# Sidekiq Asynch job queue. It loads only what the workers need.

# Start sidekiq manually with:
# bundle exec sidekiq -c 5 -v -r './config/sidekiq_boot.rb

# Heroku note. This will need to be manually started at least once:
# heroku ps:scale worker=1

# Load Dotenv as early in the boot process as possible
# Top-most files override lower files
# See : http://www.virtuouscode.com/2014/01/17/dotenv-for-multiple-environments/
# See : https://juanitofatas.com/blog/2016/08/28/manage_your_project_s_environment_variables
require 'dotenv'
env = ENV.fetch('RACK_ENV') { 'development' }
Dotenv.load(
  File.expand_path('../../.env.local', __FILE__),
  File.expand_path("../../.env.#{env}", __FILE__),
  File.expand_path('../../.env', __FILE__)
)

require 'json'
require 'redis'
require 'redis-namespace'
require 'sidekiq'
require 'sidekiq-scheduler'
require 'rollbar'
require 'tierion'

Dir.glob('./workers/*.rb').each { |file| require file }

redis_uri = URI.parse(ENV.fetch('REDIS_URL') { 'redis://127.0.0.1:6379' })
$redis = Redis.new(uri: redis_uri)

if $redis.blank?
  raise 'Exiting. The $redis client is nil.'
end

if tierion_enabled? && ENV.fetch('TIERION_USERNAME') && ENV.fetch('TIERION_PASSWORD')
  $blockchain = Tierion::HashApi::Client.new()
end

if tierion_enabled? && $blockchain.blank?
  raise 'Exiting. Tierion is enabled in this env, but $blockchain is nil. Bad auth?'
end

Sidekiq.configure_client do |config|
  config.redis = { namespace: 'sidekiq' }
end

Sidekiq.configure_server do |config|
  config.redis = { namespace: 'sidekiq' }
  config.on(:startup) do
    schedule = YAML.load_file(File.expand_path('../../config/sidekiq_scheduler.yml', __FILE__))
    Sidekiq.schedule = schedule
    Sidekiq::Scheduler.reload_schedule!
  end
end

# Register a callback URL for Tierion (optional)
if tierion_enabled? && ENV.fetch('RACK_ENV') == 'production'
  begin
    callback_uri = ENV.fetch('TIERION_SUBSCRIPTION_CALLBACK_URI')
    $blockchain.create_block_subscription(callback_uri) if callback_uri.present?
  rescue StandardError
    # no-op : duplicate registration can throw exception
  end
end

Rollbar.configure do |config|
  config.access_token = ENV.fetch('ROLLBAR_ACCESS_TOKEN')
  config.use_sidekiq 'queue' => 'default'
end

def tierion_enabled?
  ENV.fetch('TIERION_ENABLED') == 'true'
end

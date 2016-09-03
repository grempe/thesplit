require 'rollbar/rake_tasks'
require 'dotenv/tasks'

# task :mytask => :dotenv do
#     # things that require .env
# end

task :environment do
  Rollbar.configure do |config |
    config.access_token = ENV.fetch('ROLLBAR_ACCESS_TOKEN')
  end
end

begin
  require 'rspec/core/rake_task'
  require 'wwtd/tasks'

  RSpec::Core::RakeTask.new do |task|
    task.rspec_opts = ['--color', '--format', 'doc']
  end

  task default: :spec
rescue LoadError
  # no-op in production
end

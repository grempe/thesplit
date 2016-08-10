require 'rollbar/rake_tasks'

task :environment do
  Rollbar.configure do |config |
    config.access_token = ENV['ROLLBAR_ACCESS_TOKEN']
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

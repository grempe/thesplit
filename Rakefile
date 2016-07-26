require 'rspec/core/rake_task'
require 'wwtd/tasks'

RSpec::Core::RakeTask.new do |task|
  task.rspec_opts = ['--color', '--format', 'doc']
end

task default: :spec

guard :puma, port: 3000 do
  watch('Gemfile.lock')
  watch(%r{^config|controllers|models|workers|helpers/.*})
end

guard :rspec, cmd: 'bundle exec rspec' do
  watch('spec/spec_helper.rb') { 'spec' }
  watch(%r{^spec/.+_spec\.rb$})
  watch(%r{^controllers/(.+)\.rb$}) { |m| "spec/#{m[1]}_spec.rb" }
  watch(%r{^helpers/(.+)\.rb$}) { 'spec' }
  watch(%r{^models/(.+)\.rb$}) { 'spec' }
  watch(%r{^config/(.+)\.rb$}) { 'spec' }
  watch(%r{^views/(.+)\.erb$}) { 'spec' }
end

guard :puma, port: 3000 do
  watch('Gemfile.lock')
  watch(%r{^config|app/.*})
end

guard :rspec, cmd: 'bundle exec rspec' do
  watch('spec/spec_helper.rb') { 'spec' }
  watch(%r{^spec/.+_spec\.rb$})
  watch(%r{^app/(.+)\.rb$}) { |m| "spec/#{m[1]}_spec.rb" }
  watch(%r{^config/(.+)\.rb$}) { 'spec' }
  watch(%r{^views/(.+)\.erb$}) { 'spec' }
end

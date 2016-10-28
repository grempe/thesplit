# Once Puma is started it can also be controlled and gracefully
# restarted with its own control interface.
#
# via HTTP:
#
#   http://127.0.0.1:9293/stats?token=pumarules
#
# available paths:
#   stop, halt, restart, phased-restart, reload-worker-directory, stats
#
# via 'pumactl' command
#
#   pumactl --help
#
#   pumactl -S /tmp/.puma.state restart
#

web: bundle exec puma -e $RACK_ENV -p 5000 -C config/puma.rb
worker: bundle exec sidekiq -c 3 -v -r './config/sidekiq_boot.rb'

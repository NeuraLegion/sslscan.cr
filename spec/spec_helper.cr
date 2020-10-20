require "spectator"
require "spectator/should"
require "../src/sslscan"

Spectator.configure do |config|
  config.fail_blank
  config.randomize
  config.profile
end

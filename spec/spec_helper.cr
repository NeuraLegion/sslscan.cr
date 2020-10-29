require "spectator"
require "spectator/should"
require "../src/sslscan"
require "./sslscan/*"

Spectator.configure do |config|
  config.fail_blank
  config.randomize
  config.profile
end

def fixture_path(*parts : String) : Path
  Path[__DIR__, "fixtures", *parts].expand
end

def xml_fixture(*path_parts : String) : XML::Node
  content = File.read(fixture_path(*path_parts))
  XML.parse(content)
end

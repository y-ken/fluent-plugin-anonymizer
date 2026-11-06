# The CI covers Fluentd 1.20.1 and later, and the Fluentd of FLUENTD_VERSION on
# older Rubies. Fail if Bundler resolved another one.
require "fluent/version"
requirement = Gem::Requirement.new(ENV.fetch("FLUENTD_VERSION", "").empty? ? ">= 1.20.1" : ENV["FLUENTD_VERSION"])
version = Gem::Version.new(Fluent::VERSION)
puts "Fluentd #{version}"
abort "Fluentd #{requirement} is expected" unless requirement.satisfied_by?(version)

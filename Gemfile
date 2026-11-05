source "http://rubygems.org"

# Specify your gem's dependencies in fluent-plugin-anonymizer.gemspec
gemspec

# The CI runs the unit tests on an older Fluentd with FLUENTD_VERSION, such as "~> 1.16.0".
gem "fluentd", ENV["FLUENTD_VERSION"] unless ENV.fetch("FLUENTD_VERSION", "").empty?

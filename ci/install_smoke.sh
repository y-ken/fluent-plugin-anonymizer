#!/bin/sh
# Install smoke test: installs the built gem into the official fluent/fluentd
# Debian image and checks that the plugin loads and masks a record with the
# Fluentd in that image.
set -eux

GEM_FILE="${GEM_FILE:-/workspace/pkg/fluent-plugin-anonymizer.gem}"

gem install "$GEM_FILE"

# Confirm the installed plugin loads and masks a record at runtime.
ruby "$(dirname "$0")/verify_plugin_load.rb"

# Loads the installed plugin and masks a record, to confirm that the plugin
# works with the Fluentd in the image after a fresh install.
require "fluent/version"
require "fluent/test"
require "fluent/test/driver/filter"
require "fluent/plugin/filter_anonymizer"

conf = %[
  <mask sha1>
    keys member_id
    salt mysaltstring
  </mask>
  <mask network>
    keys host
    ipv4_mask_bits 24
  </mask>
]
driver = Fluent::Test::Driver::Filter.new(Fluent::Plugin::AnonymizerFilter).configure(conf)
driver.run { driver.feed("raw.dummy", Fluent::EventTime.now, { "host" => "10.102.3.80", "member_id" => "12345" }) }
record = driver.filtered_records.first

# The same values as in the README sample output (SHA1 of "mysaltstring12345").
expected = { "host" => "10.102.3.0", "member_id" => "5ab2cebb0537866c4a0cd2e2f3502c0976b788da" }
abort "unexpected record: #{record.inspect}" unless record == expected
puts "filter_anonymizer loaded with Fluentd #{Fluent::VERSION}; masked #{record.inspect}"

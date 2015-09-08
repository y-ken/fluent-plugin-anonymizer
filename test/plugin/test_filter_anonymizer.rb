require 'helper'

class AnonymizerFilterTest < Test::Unit::TestCase
  def setup
    Fluent::Test.setup
    @time = Fluent::Engine.now
  end

  CONFIG = %[
    md5_keys          data_for_md5
    sha1_keys         data_for_sha1
    sha256_keys       data_for_sha256
    sha384_keys       data_for_sha384
    sha512_keys       data_for_sha512
    hash_salt         test_salt_string
    ipaddr_mask_keys  host
    ipv4_mask_subnet  24
  ]

  def create_driver(conf=CONFIG, tag='test')
    Fluent::Test::FilterTestDriver.new(Fluent::AnonymizerFilter, tag).configure(conf)
  end

  def filter(conf, messages)
    d = create_driver(conf)
    d.run {
      messages.each {|message|
        d.filter(message, @time)
      }
    }
    filtered = d.filtered_as_array
    filtered.map {|m| m[2] }
  end

  def test_configure
    assert_raise(Fluent::ConfigError) {
      d = create_driver('')
    }
    assert_raise(Fluent::ConfigError) {
      d = create_driver('unknown_keys')
    }
    d = create_driver(CONFIG)
    assert_equal 'test_salt_string', d.instance.config['hash_salt']
  end

  def test_filter
    messages = [
      {
        'host'            => '10.102.3.80',
        'data_for_md5'    => '12345',
        'data_for_sha1'   => '12345',
        'data_for_sha256' => '12345',
        'data_for_sha384' => '12345',
        'data_for_sha512' => '12345'
      }
    ]
    expected = {
      'host'            => '10.102.3.0',
      'data_for_md5'    => 'e738cbde82a514dc60582cd467c240ed',
      'data_for_sha1'   => '69cf099459c06b852ede96d39b710027727d13c6',
      'data_for_sha256' => '804d83b8c6a3e01498d40677652b084333196d8e548ee5a8710fbd0e1e115527',
      'data_for_sha384' => '6c90c389bbdfc210416b9318df3f526b4f218f8a8df3a67020353c35da22dc154460b18f22a8009a747b3ef2975acae7',
      'data_for_sha512' => 'cdbb897e6f3a092161bdb51164eb2996b75b00555f568219628ff15cd2929865d217af5dff9c32ddc908b75a89baec96b3e9a0da120e919f5246de0f1bc54c58'
    }
    filtered = filter(CONFIG, messages)
    assert_equal(expected, filtered[0])
  end

  def test_filter_multi_keys
    conf = %[
      sha1_keys         member_id, mail, telephone
      ipaddr_mask_keys  host, host2
      ipv4_mask_subnet  16
    ]
    messages = [
      {
        'host'      => '10.102.3.80',
        'host2'     => '10.102.3.80',
        'member_id' => '12345',
        'mail'      => 'example@example.com',
        'telephone' => '00-0000-0000',
        'action'    => 'signup'
      }
    ]
    expected = {
      'host'      => '10.102.0.0',
      'host2'     => '10.102.0.0',
      'member_id' => '774472f0dc892f0b3299cae8dadacd0a74ba59d7',
      'mail'      => 'd7b728209f5dd8df10cecbced30394c3c7fc2c82',
      'telephone' => 'a67f73c395105a358a03a0f127bf64b5495e7841',
      'action'    => 'signup'
    }
    filtered = filter(conf, messages)
    assert_equal(expected, filtered[0])
  end

  def test_filter_nested_keys
    conf = %[
      sha1_keys         nested.data,nested.nested.data
      ipaddr_mask_keys  hosts.host1
      ipv4_mask_subnet  16
    ]
    messages = [
      {
        'hosts' => {
          'host1' => '10.102.3.80',
        },
        'nested' => {
          'data' => '12345',
          'nested' => {
            'data' => '12345'
          }
        }
      }
    ]
    expected = {
      'hosts' => {
        'host1' => '10.102.0.0'
      },
      'nested' => {
        'data' => '774472f0dc892f0b3299cae8dadacd0a74ba59d7',
        'nested' => {
          'data' => '774472f0dc892f0b3299cae8dadacd0a74ba59d7'
        }
      }
    }
    filtered = filter(conf, messages)
    assert_equal(expected, filtered[0])
  end

  def test_filter_nest_value
    conf = %[
      sha1_keys         array,hash
      ipaddr_mask_keys  host
    ]
    messages = [
      {
        'host' => '10.102.3.80',
        'array' => ['1000', '2000'],
        'hash' => {'foo' => '1000', 'bar' => '2000'},
      }
    ]
    expected = {
      'host' => '10.102.3.0',
      'array' => ["c1628fc0d473cb21b15607c10bdcad19d1a42e24", "ea87abc249f9f2d430edb816514bffeffd3e698e"],
      'hash' => '28fe85deb0d1d39ee14c49c62bc4773b0338247b'
    }
    filtered = filter(conf, messages)
    assert_equal(expected, filtered[0])
  end

  def test_filter_ipv6
    conf = %[
      ipaddr_mask_keys  host
      ipv4_mask_subnet  24
      ipv6_mask_subnet  104
    ]
    messages = [
      { 'host' => '10.102.3.80' },
      { 'host' => '0:0:0:0:0:FFFF:129.144.52.38' },
      { 'host' => '2001:db8:0:8d3:0:8a2e:70:7344' }
    ]
    expected = [
      { 'host' => '10.102.3.0' },
      { 'host' => '::ffff:129.0.0.0' },
      { 'host' => '2001:db8:0:8d3:0:8a2e::' }
    ]
    filtered = filter(conf, messages)
    assert_equal(expected, filtered)
  end
end


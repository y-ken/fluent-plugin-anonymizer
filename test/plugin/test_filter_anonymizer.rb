require 'helper'

class AnonymizerFilterTest < Test::Unit::TestCase
  def setup
    omit_unless(Fluent.const_defined?(:Filter))
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
      'data_for_md5'    => '9138bd41172f5485f7b6eee3afcd0d62',
      'data_for_sha1'   => 'ee98db51658d38580b1cf788db19ad06e51a32f7',
      'data_for_sha256' => 'd53d15615b19597b0f95a984a132ed5164ba9676bf3cb28e018d28feaa2ea6fd',
      'data_for_sha384' => '6e9cd6d84ea371a72148b418f1a8cb2534da114bc2186d36ec6f14fd5c237b6f2e460f409dda89b7e42a14b7da8a8131',
      'data_for_sha512' => 'adcf4e5d1e52f57f67d8b0cd85051158d7362103d7ed4cb6302445c2708eff4b17cb309cf5d09fd5cf76615c75652bd29d1707ce689a28e8700afd7a7439ef20'
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
      'member_id' => '8cb2237d0679ca88db6464eac60da96345513964',
      'mail'      => '914fec35ce8bfa1a067581032f26b053591ee38a',
      'telephone' => 'ce164718b94212332187eb8420903b46b334d609',
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


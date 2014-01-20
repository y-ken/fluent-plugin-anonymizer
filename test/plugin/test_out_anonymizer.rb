require 'helper'

class AnonymizerOutputTest < Test::Unit::TestCase
  def setup
    Fluent::Test.setup
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
    remove_tag_prefix input.
    add_tag_prefix    anonymized.
  ]

  def create_driver(conf=CONFIG,tag='test')
    Fluent::Test::OutputTestDriver.new(Fluent::AnonymizerOutput, tag).configure(conf)
  end

  def test_configure
    assert_raise(Fluent::ConfigError) {
      d = create_driver('')
    }
    assert_raise(Fluent::ConfigError) {
      d = create_driver('unknown_keys')
    }
    d = create_driver(CONFIG)
    puts d.instance.inspect
    assert_equal 'test_salt_string', d.instance.config['hash_salt']
  end

  def test_emit
    d1 = create_driver(CONFIG, 'input.access')
    d1.run do
      d1.emit({
        'host' => '10.102.3.80',
        'data_for_md5' => '12345',
        'data_for_sha1' => '12345',
        'data_for_sha256' => '12345',
        'data_for_sha384' => '12345',
        'data_for_sha512' => '12345'
      })
    end
    emits = d1.emits
    assert_equal 1, emits.length
    p emits[0]
    assert_equal 'anonymized.access', emits[0][0] # tag
    assert_equal '10.102.3.0', emits[0][2]['host']
    assert_equal 'e738cbde82a514dc60582cd467c240ed', emits[0][2]['data_for_md5']
    assert_equal '69cf099459c06b852ede96d39b710027727d13c6', emits[0][2]['data_for_sha1']
    assert_equal '804d83b8c6a3e01498d40677652b084333196d8e548ee5a8710fbd0e1e115527', emits[0][2]['data_for_sha256']
    assert_equal '6c90c389bbdfc210416b9318df3f526b4f218f8a8df3a67020353c35da22dc154460b18f22a8009a747b3ef2975acae7', emits[0][2]['data_for_sha384']
    assert_equal 'cdbb897e6f3a092161bdb51164eb2996b75b00555f568219628ff15cd2929865d217af5dff9c32ddc908b75a89baec96b3e9a0da120e919f5246de0f1bc54c58', emits[0][2]['data_for_sha512']
  end

  def test_emit_multi_keys
    d1 = create_driver(%[
      sha1_keys         member_id, mail, telephone
      ipaddr_mask_keys  host, host2
      ipv4_mask_subnet  16
      remove_tag_prefix input.
      add_tag_prefix    anonymized.
    ], 'input.access')
    d1.run do
      d1.emit({
        'host' => '10.102.3.80',
        'host2' => '10.102.3.80',
        'member_id' => '12345',
        'mail' => 'example@example.com',
        'telephone' => '00-0000-0000',
        'action' => 'signup'
      })
    end
    emits = d1.emits
    assert_equal 1, emits.length
    p emits[0]
    assert_equal 'anonymized.access', emits[0][0] # tag
    assert_equal '10.102.0.0', emits[0][2]['host']
    assert_equal '10.102.0.0', emits[0][2]['host2']
    assert_equal '774472f0dc892f0b3299cae8dadacd0a74ba59d7', emits[0][2]['member_id']
    assert_equal 'd7b728209f5dd8df10cecbced30394c3c7fc2c82', emits[0][2]['mail']
    assert_equal 'a67f73c395105a358a03a0f127bf64b5495e7841', emits[0][2]['telephone']
    assert_equal 'signup', emits[0][2]['action']
  end

  def test_emit_nest_value
    d1 = create_driver(%[
      sha1_keys         array,hash
      ipaddr_mask_keys  host
      remove_tag_prefix input.
      add_tag_prefix    anonymized.
    ], 'input.access')
    d1.run do
      d1.emit({
        'host' => '10.102.3.80',
        'array' => ['1000', '2000'],
        'hash' => {'foo' => '1000', 'bar' => '2000'},
      })
    end
    emits = d1.emits
    assert_equal 1, emits.length
    p emits[0]
    assert_equal 'anonymized.access', emits[0][0] # tag
    assert_equal '10.102.3.0', emits[0][2]['host']
    assert_equal ["c1628fc0d473cb21b15607c10bdcad19d1a42e24", "ea87abc249f9f2d430edb816514bffeffd3e698e"], emits[0][2]['array']
    assert_equal '28fe85deb0d1d39ee14c49c62bc4773b0338247b', emits[0][2]['hash']
  end

  def test_emit_ipv6
    d1 = create_driver(%[
      ipaddr_mask_keys  host
      ipv4_mask_subnet  24
      ipv6_mask_subnet  104
      remove_tag_prefix input.
      add_tag_prefix    anonymized.
    ], 'input.access')
    d1.run do
      d1.emit({'host' => '10.102.3.80'})
      d1.emit({'host' => '0:0:0:0:0:FFFF:129.144.52.38'})
      d1.emit({'host' => '2001:db8:0:8d3:0:8a2e:70:7344'})
    end
    emits = d1.emits
    assert_equal 3, emits.length
    p emits
    assert_equal 'anonymized.access', emits[0][0] # tag
    assert_equal '10.102.3.0', emits[0][2]['host']
    assert_equal '::ffff:129.0.0.0', emits[1][2]['host']
    assert_equal '2001:db8:0:8d3:0:8a2e::', emits[2][2]['host']
  end

  def test_emit_tag_static
    d1 = create_driver(%[
      sha1_keys         member_id
      tag               anonymized.message
    ], 'input.access')
    d1.run do
      d1.emit({
        'member_id' => '12345',
      })
    end
    emits = d1.emits
    assert_equal 1, emits.length
    p emits[0]
    assert_equal 'anonymized.message', emits[0][0] # tag
    assert_equal '774472f0dc892f0b3299cae8dadacd0a74ba59d7', emits[0][2]['member_id']
  end

  def test_emit_tag_placeholder
    d1 = create_driver(%[
      sha1_keys         member_id
      tag               anonymized.${tag}
      remove_tag_prefix input.
    ], 'input.access')
    d1.run do
      d1.emit({
        'member_id' => '12345',
      })
    end
    emits = d1.emits
    assert_equal 1, emits.length
    p emits[0]
    assert_equal 'anonymized.access', emits[0][0] # tag
    assert_equal '774472f0dc892f0b3299cae8dadacd0a74ba59d7', emits[0][2]['member_id']
  end
end

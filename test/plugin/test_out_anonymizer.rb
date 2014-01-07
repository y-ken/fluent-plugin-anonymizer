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

  CONFIG_MULTI_KEYS = %[
    sha1_keys         member_id, mail, telephone
    ipaddr_mask_keys  host
    ipv4_mask_subnet  16
    remove_tag_prefix input.
    add_tag_prefix    anonymized.
  ]

  CONFIG_NEST_VALUE = %[
    sha1_keys         array,hash
    ipaddr_mask_keys  host
    remove_tag_prefix input.
    add_tag_prefix    anonymized.
  ]

  CONFIG_IPV6 = %[
    ipaddr_mask_keys  host
    ipv4_mask_subnet  24
    ipv6_mask_subnet  104
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
    assert_equal '9138bd41172f5485f7b6eee3afcd0d62', emits[0][2]['data_for_md5']
    assert_equal 'ee98db51658d38580b1cf788db19ad06e51a32f7', emits[0][2]['data_for_sha1']
    assert_equal 'd53d15615b19597b0f95a984a132ed5164ba9676bf3cb28e018d28feaa2ea6fd', emits[0][2]['data_for_sha256']
    assert_equal '6e9cd6d84ea371a72148b418f1a8cb2534da114bc2186d36ec6f14fd5c237b6f2e460f409dda89b7e42a14b7da8a8131', emits[0][2]['data_for_sha384']
    assert_equal 'adcf4e5d1e52f57f67d8b0cd85051158d7362103d7ed4cb6302445c2708eff4b17cb309cf5d09fd5cf76615c75652bd29d1707ce689a28e8700afd7a7439ef20', emits[0][2]['data_for_sha512']
  end

  def test_emit_multi_keys
    d1 = create_driver(CONFIG_MULTI_KEYS, 'input.access')
    d1.run do
      d1.emit({
        'host' => '10.102.3.80',
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
    assert_equal '8cb2237d0679ca88db6464eac60da96345513964', emits[0][2]['member_id']
    assert_equal '914fec35ce8bfa1a067581032f26b053591ee38a', emits[0][2]['mail']
    assert_equal 'ce164718b94212332187eb8420903b46b334d609', emits[0][2]['telephone']
    assert_equal 'signup', emits[0][2]['action']
  end

  def test_emit_nest_value
    d1 = create_driver(CONFIG_NEST_VALUE, 'input.access')
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
    assert_equal ["e3cbba8883fe746c6e35783c9404b4bc0c7ee9eb", "a4ac914c09d7c097fe1f4f96b897e625b6922069"], emits[0][2]['array']
    assert_equal '1a1903d78aed9403649d61cb21ba6b489249761b', emits[0][2]['hash']
  end

  def test_emit_ipv6
    d1 = create_driver(CONFIG_IPV6, 'input.access')
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
end

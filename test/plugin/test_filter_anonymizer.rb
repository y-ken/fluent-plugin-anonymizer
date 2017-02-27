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
        d.emit(message, @time)
      }
    }
    filtered = d.filtered_as_array
    filtered.map {|m| m[2] }
  end

  require 'ostruct'
  test 'method md5 works correctly' do
    conv = Fluent::AnonymizerFilter::MASK_METHODS[:md5].call(OpenStruct.new)
    digest = conv.call('value1', 'salt')
    assert_equal 'd21fe9523421f12daad064fd082913fd', digest
  end
  test 'method sha1 works correctly' do
    conv = Fluent::AnonymizerFilter::MASK_METHODS[:sha1].call(OpenStruct.new)
    digest = conv.call('value2', 'salt')
    assert_equal 'd2ed8e797065322371012fd8c1a39682987ddb71', digest
  end
  test 'method sha256 works correctly' do
    conv = Fluent::AnonymizerFilter::MASK_METHODS[:sha256].call(OpenStruct.new)
    digest = conv.call('value3', 'salt')
    assert_equal 'd70daf9654b8a3ba335f8f9f9638a93e8eba6763a0012ac44a928857871abe82', digest
  end
  test 'method sha384 works correctly' do
    conv = Fluent::AnonymizerFilter::MASK_METHODS[:sha384].call(OpenStruct.new)
    digest = conv.call('value4', 'salt')
    assert_equal '646192f8b1ea905238df589a00a10598a53eb245df4ab14b7e9eccf80c37386c99abe5259ccb2ba950003423fa0790ee', digest
  end
  test 'method sha512 works correctly' do
    conv = Fluent::AnonymizerFilter::MASK_METHODS[:sha512].call(OpenStruct.new)
    digest = conv.call('value5', 'salt')
    expected = '47c82bfea3783c20e3ba3629f0f827bebf0fa65a9104ada5339e5776e5958f061fe7114bfbe1e9d410aff43c6bee8365adf4fdd072e54ab4fffad820f354f545'
    assert_equal expected, digest
  end
  test 'method uri_path removes path, query parameters, fragment, user and password of uri strings' do
    conv = Fluent::AnonymizerFilter::MASK_METHODS[:uri_path].call(OpenStruct.new)
    assert_equal '/my/path', conv.call('/my/path', '')
    assert_equal 'yay/unknown/format', conv.call('yay/unknown/format', '')
    assert_equal 'http://example.com/', conv.call('http://example.com/path/to/secret', '')
    assert_equal 'http://example.com/', conv.call('http://example.com/path/to/secret?a=b', '')
    assert_equal 'http://example.com/', conv.call('http://example.com/path/to/secret#xxx', '')
    assert_equal 'http://example.com/', conv.call('http://example.com/path/to/secret?a=b#xxx', '')
    assert_equal 'http://example.com/', conv.call('http://tagomoris:secret!@example.com/', '')
    assert_equal 'http://example.com/', conv.call('http://tagomoris:secret!@example.com/?a=b#xxx', '')
    assert_equal 'http://example.com/', conv.call('http://tagomoris:secret!@example.com/path/to/secret?a=b#xxx', '')
  end
  test 'method network masks ipaddresses with specified mask bit lengths' do
    conf = OpenStruct.new(ipv4_mask_bits: 24, ipv6_mask_bits: 104)
    conv = Fluent::AnonymizerFilter::MASK_METHODS[:network].call(conf)
    assert_equal '192.168.1.0', conv.call('192.168.1.1', '')
    assert_equal '10.110.18.0', conv.call('10.110.18.9', '')
    assert_equal '2001:db8:0:8d3:0:8a2e::', conv.call('2001:db8:0:8d3:0:8a2e:70:7344', '')
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

  test 'masker_for_key generates a lambda for conversion with exact key match' do
    conf = OpenStruct.new(salt: 's')
    plugin = create_driver.instance
    conv = ->(v,salt){ "#{v.upcase}:#{salt}" } # it's dummy for test
    masker = plugin.masker_for_key(conv, 'kkk', conf)
    r = masker.call({"k" => "x", "kk" => "xx", "kkk" => "xxx", "kkkk" => "xxxx"})
    assert_equal "x", r["k"]
    assert_equal "xx", r["kk"]
    assert_equal "XXX:s", r["kkk"]
    assert_equal "xxxx", r["kkkk"]
    assert_equal 4, r.size
  end

  test 'masker_for_key_chain generates a lambda for conversion with recursive key fetching' do
    conf = OpenStruct.new(salt: 's')
    plugin = create_driver.instance
    conv = ->(v,salt){ "#{v.upcase}:#{salt}" } # it's dummy for test
    masker = plugin.masker_for_key_chain(conv, 'a.b.c'.split('.'), conf)
    event = {
      'a' => {
        'b' => { 'c' => 'v', 'd' => 'v' }
      }
    }
    r = masker.call(event)
    assert_equal 'V:s', r['a']['b']['c']
    assert_equal 'v', r['a']['b']['d']
  end

  test 'masker_for_key_pattern generates a lambda for conversion with key pattern match' do
    conf = OpenStruct.new(salt: 's')
    plugin = create_driver.instance
    conv = ->(v,salt){ "#{v.upcase}:#{salt}" } # it's dummy for test
    masker = plugin.masker_for_key_pattern(conv, '^k+$', conf)
    r = masker.call({"k" => "x", "kk" => "xx", "kkk" => "xxx", "kkk0" => "xxxx", "f" => "x", "ff" => "xx"})
    assert_equal "X:s", r["k"]
    assert_equal "XX:s", r["kk"]
    assert_equal "XXX:s", r["kkk"]
    assert_equal "xxxx", r["kkk0"]
    assert_equal "x", r["f"]
    assert_equal "xx", r["ff"]
    assert_equal 6, r.size
  end

  test 'masker_for_value_pattern' do
    conf = OpenStruct.new(salt: 's')
    plugin = create_driver.instance
    conv = ->(v,salt){ "#{v.upcase}:#{salt}" } # it's dummy for test
    masker = plugin.masker_for_value_pattern(conv, '^x+$', conf)
    r = masker.call({"k" => "x", "kk" => "x0", "kkk" => "xx0", "kkk0" => "xxxx", "f" => "x", "ff" => "xx"})
    assert_equal "X:s", r["k"]
    assert_equal "x0", r["kk"]
    assert_equal "xx0", r["kkk"]
    assert_equal "XXXX:s", r["kkk0"]
    assert_equal "X:s", r["f"]
    assert_equal "XX:s", r["ff"]
    assert_equal 6, r.size
  end

  test 'masker_for_value_in_subnet' do
    conf = OpenStruct.new(salt: 's')
    plugin = create_driver.instance
    conv = ->(v,salt){ "#{v.upcase}:#{salt}" } # it's dummy for test
    masker = plugin.masker_for_value_in_subnet(conv, '192.168.0.0/16', conf)
    r = masker.call({"k1" => "x", "k2" => "192.169.1.1", "k3" => "192.168.128.13", "f1" => "x", "f2" => "10.0.12.1", "f3" => "192.168.1.1"})
    assert_equal "x", r["k1"]
    assert_equal "192.169.1.1", r["k2"]
    assert_equal "192.168.128.13:s", r["k3"]
    assert_equal "x", r["f1"]
    assert_equal "10.0.12.1", r["f2"]
    assert_equal "192.168.1.1:s", r["f3"]
  end

  test 'filter plugin can mask specified fields' do
    plugin = create_driver(<<-CONF).instance
      <mask md5>
        salt testing
        key  test
      </mask>
CONF
    r = plugin.filter('tag', Time.now.to_i, {"test" => "value", "name" => "fluentd plugin"})
    assert_equal 2, r.size
    assert_equal "fluentd plugin", r["name"]
    assert_equal "6255093f2e4204e24df48ddd7f4a8abe", r["test"]
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
        'data' => '8cb2237d0679ca88db6464eac60da96345513964',
        'nested' => {
          'data' => '8cb2237d0679ca88db6464eac60da96345513964'
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
      'array' => ["e3cbba8883fe746c6e35783c9404b4bc0c7ee9eb", "a4ac914c09d7c097fe1f4f96b897e625b6922069"],
      'hash' => '1a1903d78aed9403649d61cb21ba6b489249761b'
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


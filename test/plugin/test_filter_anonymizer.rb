require 'helper'
require 'fluent/test/driver/filter'
require 'fluent/plugin/filter_anonymizer'

class AnonymizerFilterTest < Test::Unit::TestCase
  def setup
    omit_unless(Fluent.const_defined?(:Filter))
    Fluent::Test.setup
    @time = Fluent::Engine.now
  end

  CONFIG = %[
    <mask md5>
      keys data_for_md5
      salt test_salt_string
    </mask>
    <mask sha1>
      keys data_for_sha1
      salt test_salt_string
    </mask>
    <mask sha256>
      keys data_for_sha256
      salt test_salt_string
    </mask>
    <mask sha384>
      keys data_for_sha384
      salt test_salt_string
    </mask>
    <mask sha512>
      keys data_for_sha512
      salt test_salt_string
    </mask>
    <mask network>
      keys           host
      ipv4_mask_bits 24
      salt           test_salt_string
    </mask>
  ]

  def create_driver(conf=CONFIG)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::AnonymizerFilter).configure(conf)
  end

  def filter(conf, messages)
    d = create_driver(conf)
    d.run(default_tag: 'test') {
      messages.each {|message|
        d.feed(@time, message)
      }
    }
    filtered = d.filtered
    filtered.map {|m| m.last }
  end

  require 'ostruct'
  test 'method md5 works correctly' do
    conv = Fluent::Plugin::AnonymizerFilter::MASK_METHODS[:md5].call(OpenStruct.new)
    digest = conv.call('value1', 'salt')
    assert_equal 'd21fe9523421f12daad064fd082913fd', digest
  end
  test 'method sha1 works correctly' do
    conv = Fluent::Plugin::AnonymizerFilter::MASK_METHODS[:sha1].call(OpenStruct.new)
    digest = conv.call('value2', 'salt')
    assert_equal 'd2ed8e797065322371012fd8c1a39682987ddb71', digest
  end
  test 'method sha256 works correctly' do
    conv = Fluent::Plugin::AnonymizerFilter::MASK_METHODS[:sha256].call(OpenStruct.new)
    digest = conv.call('value3', 'salt')
    assert_equal 'd70daf9654b8a3ba335f8f9f9638a93e8eba6763a0012ac44a928857871abe82', digest
  end
  test 'method sha384 works correctly' do
    conv = Fluent::Plugin::AnonymizerFilter::MASK_METHODS[:sha384].call(OpenStruct.new)
    digest = conv.call('value4', 'salt')
    assert_equal '646192f8b1ea905238df589a00a10598a53eb245df4ab14b7e9eccf80c37386c99abe5259ccb2ba950003423fa0790ee', digest
  end
  test 'method sha512 works correctly' do
    conv = Fluent::Plugin::AnonymizerFilter::MASK_METHODS[:sha512].call(OpenStruct.new)
    digest = conv.call('value5', 'salt')
    expected = '47c82bfea3783c20e3ba3629f0f827bebf0fa65a9104ada5339e5776e5958f061fe7114bfbe1e9d410aff43c6bee8365adf4fdd072e54ab4fffad820f354f545'
    assert_equal expected, digest
  end
  test 'method uri_path removes path, query parameters, fragment, user and password of uri strings' do
    conv = Fluent::Plugin::AnonymizerFilter::MASK_METHODS[:uri_path].call(OpenStruct.new)
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
    conv = Fluent::Plugin::AnonymizerFilter::MASK_METHODS[:network].call(conf)
    assert_equal '192.168.1.0', conv.call('192.168.1.1', '')
    assert_equal '10.110.18.0', conv.call('10.110.18.9', '')
    assert_equal '2001:db8:0:8d3:0:8a2e::', conv.call('2001:db8:0:8d3:0:8a2e:70:7344', '')
  end

  sub_test_case "configure" do
    test "empty config" do
      assert_raise(Fluent::ConfigError) {
        create_driver('')
      }
    end

    test "unknown keys" do
      assert_raise(Fluent::ConfigError) {
        create_driver('unknown_keys')
      }
    end

    test "basic config" do
      d = create_driver(CONFIG)
      assert_equal 'test_salt_string', d.instance.mask_config_list.first['salt']
    end
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
    masker = plugin.masker_for_key_chain(conv, ['a', 'b', 'c'], conf)
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

  test 'masker_for_value_pattern matches a Hash in the format before Ruby 3.4' do
    conf = OpenStruct.new(salt: 's')
    plugin = create_driver.instance
    conv = ->(v,salt){ "masked:#{salt}" } # it's dummy for test
    masker = plugin.masker_for_value_pattern(conv, '"k"=>"v"', conf)
    r = masker.call({"h" => {"k" => "v"}, "s" => "x"})
    assert_equal "masked:s", r["h"]
    assert_equal "x", r["s"]
  end

  test 'stringify writes a Hash and an Array as Ruby 3.3 inspects them' do
    stringify = Fluent::Plugin::AnonymizerFilter.method(:stringify)
    assert_equal 'abc', stringify.call('abc')
    assert_equal '12', stringify.call(12)
    assert_equal '', stringify.call(nil)
    assert_equal '{}', stringify.call({})
    assert_equal '[]', stringify.call([])
    assert_equal '{"a"=>{"b"=>[1, {"c"=>nil}], "d"=>2.5}, "e"=>[]}',
                 stringify.call({"a" => {"b" => [1, {"c" => nil}], "d" => 2.5}, "e" => []})
    assert_equal '[{"x"=>1}, "y"]', stringify.call([{"x" => 1}, "y"])
    assert_equal '{:sym=>1, :"foo bar"=>"x", 1=>2, nil=>true}',
                 stringify.call({:sym => 1, :"foo bar" => "x", 1 => 2, nil => true})
    assert_equal '{"q\\"d"=>"new\\nline"}', stringify.call({"q\"d" => "new\nline"})
  end

  test 'stringify is public and its helpers are private' do
    assert_true Fluent::Plugin::AnonymizerFilter.respond_to?(:stringify)
    assert_false Fluent::Plugin::AnonymizerFilter.respond_to?(:inspect_before_ruby34)
    assert_false Fluent::Plugin::AnonymizerFilter.respond_to?(:plain_container?)
  end

  # The expected strings are in the format of to_s on Ruby 3.3. Each pattern
  # for value_pattern does not start with a quote, which the config parser
  # would read as a quoted string.
  DEEP = 3000
  NESTED_VALUES = {
    "Hash nested 3,000 levels deep" => [
      -> { v = "alice"; DEEP.times { v = {"k" => v} }; v },
      '{"k"=>' * DEEP + '"alice"' + '}' * DEEP,
      'alice',
    ],
    "Array nested 3,000 levels deep" => [
      -> { v = "alice"; DEEP.times { v = [v] }; v },
      '[' * DEEP + '"alice"' + ']' * DEEP,
      'alice',
    ],
    "direct cycle of a Hash" => [
      -> { h = {"a" => 1}; h["self"] = h; h },
      '{"a"=>1, "self"=>{...}}',
      'self"=>\{\.\.\.\}\}$',
    ],
    "direct cycle of an Array" => [
      -> { a = [1]; a << a; a },
      '[1, [...]]',
      '^\[1, \[\.\.\.\]\]$',
    ],
    "indirect cycle" => [
      -> { h1 = {}; h2 = {}; h1["x"] = h2; h2["x"] = h1; h1 },
      '{"x"=>{"x"=>{...}}}',
      '^\{"x"=>\{"x"=>\{\.\.\.\}\}\}$',
    ],
    "indirect cycle through an Array" => [
      -> { a = []; a << {"y" => a} << 2; a },
      '[{"y"=>[...]}, 2]',
      'y"=>\[\.\.\.\]\}, 2\]$',
    ],
    "shared container that is not a cycle" => [
      -> { s = {"k" => "v"}; l = [1, s]; {"a" => s, "b" => s, "c" => [l, l]} },
      '{"a"=>{"k"=>"v"}, "b"=>{"k"=>"v"}, "c"=>[[1, {"k"=>"v"}], [1, {"k"=>"v"}]]}',
      'b"=>\{"k"=>"v"\}, "c"=>\[\[1, \{"k"=>"v"\}\], \[1, \{',
    ],
  }

  def sha256(salt, str)
    OpenSSL::Digest.new("sha256").update(salt).update(str).hexdigest
  end

  class HashWithInspect < Hash
    def inspect; "HASH"; end
  end
  class ArrayWithInspect < Array
    def inspect; "ARRAY"; end
  end
  class PlainSubHash < Hash; end
  class InspectNil
    def inspect; nil; end
  end
  class InspectInteger
    def inspect; 65; end
  end
  class HashWithMethodKey < Hash
    def method; self["method"]; end
  end
  class HashFakingClass < Hash
    def inspect; "FAKE"; end
    def class; Hash; end
  end
  class BasicWithInspect < BasicObject
    def inspect; "BASIC"; end
  end
  module InspectModule
    def inspect; "MODULE"; end
  end
  module ToSModule
    def to_s; "MODULE_TO_S"; end
  end

  # The values in the review of #37. Each is not plain, so it uses to_s of the
  # running Ruby, as master does.
  class StringWithToS < String
    def to_s; "alice"; end
  end
  class ArrayWithIndex < Array
    def [](i); "bob"; end
  end
  class HashWithKeys < Hash
    def keys; ["other"]; end
    def values; ["bob"]; end
  end
  class PrivateInspect
    def inspect; "alice"; end
    private :inspect
  end
  class PrivateToS
    def to_s; "alice"; end
    private :to_s
  end
  class InspectPrivateToS
    def inspect; PrivateToS.new; end
  end
  class InspectUTF16
    def inspect; "alice".encode("UTF-16LE"); end
  end
  StructRef = Struct.new(:ref)
  class InspectAppends
    def initialize(array); @array = array; end
    def inspect; @array << "alice"; "first"; end
  end
  class InspectNonASCII
    def inspect; "é"; end
  end

  # Each value is built anew for each call, because inspect may change it.
  NOT_PLAIN_VALUES = {
    "nested subclass with its own inspect" => -> { {"h" => HashWithInspect["k", "v"], "a" => [ArrayWithInspect[1]]} },
    "subclass with its own inspect, but not to_s" => -> { HashWithInspect["k", "v"] },
    "subclass without its own inspect" => -> { [PlainSubHash["k", [PlainSubHash["x", 1]]]] },
    "inspect that returns nil" => -> { [InspectNil.new] },
    "inspect that returns an Integer" => -> { {"k" => InspectInteger.new} },
    "subclass with a method named method" => -> { [HashWithMethodKey["method", "GET"], {"a" => HashWithMethodKey["method", "PUT"]}] },
    "subclass that returns Hash from class" => -> { [HashFakingClass["k", 1]] },
    "BasicObject" => -> { [BasicWithInspect.new] },
    "singleton inspect" => -> { h = {"k" => "v"}; def h.inspect; "SINGLE"; end; {"h" => h} },
    "singleton to_s" => -> { h = {"k" => "v"}; def h.to_s; "SINGLE_TO_S"; end; h },
    "inspect from extend" => -> { [{"k" => "v"}.extend(InspectModule)] },
    "to_s from extend" => -> { {"k" => "v"}.extend(ToSModule) },
    "String subclass with its own to_s" => -> { StringWithToS.new("raw") },
    "Array subclass with its own []" => -> { ArrayWithIndex["alice"] },
    "Hash subclass with its own keys and values" => -> { HashWithKeys["secret", "alice"] },
    "private inspect" => -> { [PrivateInspect.new] },
    "inspect that returns a value with a private to_s" => -> { [InspectPrivateToS.new] },
    "inspect that returns UTF-16LE" => -> { [InspectUTF16.new] },
    "Struct with a cycle" => -> { a = []; a << StructRef.new(a); a },
    "inspect that adds to the Array" => -> { a = []; a << InspectAppends.new(a); a },
    "String subclass inside" => -> { {"k" => StringWithToS.new("raw")} },
    "Struct holding a Hash" => -> { [StructRef.new({"k" => "v"})] },
    "inspect undefined, with method_missing" => -> {
      h = {"k" => "v"}
      h.singleton_class.send(:undef_method, :inspect)
      def h.method_missing(*); "MISSING"; end
      [h]
    },
    "to_s undefined, with method_missing" => -> {
      h = {"k" => "v"}
      h.singleton_class.send(:undef_method, :to_s)
      def h.method_missing(*); "MISSING"; end
      h
    },
  }

  data(NOT_PLAIN_VALUES)
  test 'stringify uses to_s for a value that is not plain' do |build|
    assert_equal build.call.to_s, Fluent::Plugin::AnonymizerFilter.stringify(build.call)
  end

  data(NOT_PLAIN_VALUES)
  test 'keys masks a value that is not plain with sha256 of to_s' do |build|
    conf = %[
      <mask sha256>
        keys secret
        salt s
      </mask>
    ]
    filtered = filter(conf, [{"secret" => build.call}])
    assert_equal [{"secret" => sha256("s", build.call.to_s)}], filtered
  end

  # Ruby escapes a result of inspect that is not ASCII-only and not in the
  # default encoding.
  test 'stringify follows the escape of a result of inspect in another encoding' do
    verbose, $VERBOSE = $VERBOSE, nil
    external, internal = Encoding.default_external, Encoding.default_internal
    Encoding.default_external = Encoding::US_ASCII
    Encoding.default_internal = nil
    # Ruby writes "\u00E9" for the inspect of this object.
    assert_equal '[\u00E9]', [InspectNonASCII.new].to_s
    assert_equal '[\u00E9]', Fluent::Plugin::AnonymizerFilter.stringify([InspectNonASCII.new])
    # String#inspect escapes it by itself, so the old format is kept.
    assert_equal '{"k"=>"\u00E9"}', Fluent::Plugin::AnonymizerFilter.stringify({"k" => "\u00e9"})
  ensure
    Encoding.default_external = external
    Encoding.default_internal = internal
    $VERBOSE = verbose
  end

  test 'stringify writes a value with characters in the default encoding in the old format' do
    omit_unless(Encoding.default_external == Encoding::UTF_8 && Encoding.default_internal.nil?)
    assert_equal "{\"k\"=>\"é\"}", Fluent::Plugin::AnonymizerFilter.stringify({"k" => "é"})
  end

  data(NESTED_VALUES)
  test 'stringify writes deep, cyclic and shared values without recursion' do |(build, expected, _)|
    assert_equal expected, Fluent::Plugin::AnonymizerFilter.stringify(build.call)
  end

  data(NESTED_VALUES)
  test 'keys masks deep, cyclic and shared values with sha256' do |(build, expected, _)|
    conf = %[
      <mask sha256>
        keys secret
        salt s
      </mask>
    ]
    filtered = filter(conf, [{"n" => 1, "secret" => build.call}])
    assert_equal [{"n" => 1, "secret" => sha256("s", expected)}], filtered
  end

  data(NESTED_VALUES)
  test 'value_pattern masks deep, cyclic and shared values with sha256' do |(build, expected, pattern)|
    conf = %[
      <mask sha256>
        value_pattern #{pattern}
        salt s
      </mask>
    ]
    filtered = filter(conf, [{"n" => 1, "secret" => build.call}])
    assert_equal [{"n" => 1, "secret" => sha256("s", expected)}], filtered
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
        keys test
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
      <mask sha1>
        keys member_id, mail, telephone
        salt ""
      </mask>
      <mask network>
        keys           host, host2
        ipv4_mask_bits 16
      </mask>
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

  data("new style" => {
         "sha1" => "$.nested.data,$.nested.nested.data",
         "network" => "$.hosts.host1",
       },
       "bracket style"=> {
         "sha1" => "$['nested']['data'],$['nested']['nested']['data']",
         "network" => "$['hosts']['host1']",
       }
      )
  def test_filter_nested_keys(data)
    conf = %[
      <mask sha1>
        keys #{data["sha1"]}
        salt ""
      </mask>
      <mask network>
        keys           #{data["network"]}
        ipv4_mask_bits 16
      </mask>
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
      <mask sha1>
        keys                array, hash
        mask_array_elements true
        salt                ""
      </mask>
      <mask network>
        keys           host
        ipv4_mask_bits 24
      </mask>
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
      # The same digest on every Ruby version, though Ruby 3.4 changed Hash#inspect.
      'hash' => '1a1903d78aed9403649d61cb21ba6b489249761b'
    }
    filtered = filter(conf, messages)
    assert_equal(expected, filtered[0])
  end

  def test_filter_ipv6
    conf = %[
      <mask network>
        keys           host
        ipv4_mask_bits 24
        ipv6_mask_bits 104
      </mask>
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

  # The configurations of v1.0.0. Each expected record is the output of
  # fluent-plugin-anonymizer 1.0.0 on Ruby 2.7 for V1_INPUT. It holds only the
  # top-level keys that v1.0.0 changed.
  V1_INPUT = {
    "host" => "10.102.3.80", "host6" => "2001:db8:0:8d3:0:8a2e:70:7344", "mapped" => "::ffff:129.144.52.38",
    "not_ip" => "localhost", "ips" => ["10.1.2.3", "2001:db8::1"], "user_id" => "alice", "member_id" => "12345",
    "mail" => "example@example.com", "num" => 42, "null" => nil, "false" => false, "empty" => "",
    "list" => ["1000", "2000"], "hash" => {"k" => "v"}, "user.name" => "flat", "user id" => "spaced",
    "nest" => {"id" => "42", "ip" => "192.168.1.10", "null" => nil, "deep" => {"id" => "7"}},
  }
  V1_CONFIGS = {
    # keys is not deprecated, but its output had changed from v1.0.0.
    "keys with a dot, null and false" => [
      "<mask sha1>\n  keys user.name, null, false\n  salt s\n</mask>",
      {"null"=>"a0f1490a20d0211c997b44bc357e1972deab8ae3", "false"=>"60c2454acc39438e4dd40f221d576191fa5312f3", "user.name"=>"e3a633c4aa4f56f1782b222125030d280351ec2e"},
    ],
  }

  sub_test_case "configurations of v1.0.0" do
    data(V1_CONFIGS)
    test "output the same records as v1.0.0" do |(conf, changed)|
      d = create_driver(conf)
      d.run(default_tag: 'test') { d.feed(@time, Marshal.load(Marshal.dump(V1_INPUT))) }
      assert_equal [V1_INPUT.merge(changed)], d.filtered_records
      assert_equal [], d.logs.grep(/\[error\]/)
    end
  end

  sub_test_case "keys" do
    test "keys without $ is a top-level key even with a dot, as v1.0.0" do
      d = create_driver("<mask sha1>\n  keys a.b\n  salt s\n</mask>")
      d.run(default_tag: 'test') { d.feed(@time, {"a" => {"b" => "nested"}}) }
      assert_equal [{"a" => {"b" => "nested"}}], d.filtered_records
    end

    data("dot" => "$.a", "bracket" => "$['a']")
    test "keys with one key of record_accessor is a top-level key" do |key|
      d = create_driver("<mask sha1>\n  keys #{key}\n  salt s\n</mask>")
      d.run(default_tag: 'test') { d.feed(@time, {"a" => "alice", "b" => nil}) }
      assert_equal [{"a" => OpenSSL::Digest.new("sha1").update("s").update("alice").hexdigest, "b" => nil}], d.filtered_records
      assert_equal [], d.logs.grep(/\[error\]/)
    end

    test "keys with a value that is not a String starts, as v1.0.0" do
      d = create_driver("<mask sha1>\n  keys [123, \"user_id\"]\n  salt s\n</mask>")
      d.run(default_tag: 'test') { d.feed(@time, {"user_id" => "alice", "123" => "x"}) }
      assert_equal [{"user_id" => OpenSSL::Digest.new("sha1").update("s").update("alice").hexdigest, "123" => "x"}], d.filtered_records
    end

    test "keys of record_accessor masks null in an existing key and an element of an Array" do
      d = create_driver("<mask sha1>\n  keys $.a.n, $.a.missing, $.list[1], $.list[5], $.a.b.c\n  salt s\n</mask>")
      d.run(default_tag: 'test') { d.feed(@time, {"a" => {"n" => nil, "b" => "x"}, "list" => ["x", "y"]}) }
      sha1 = ->(v) { OpenSSL::Digest.new("sha1").update("s").update(v).hexdigest }
      assert_equal [{"a" => {"n" => sha1.(""), "b" => "x"}, "list" => ["x", sha1.("y")]}], d.filtered_records
      assert_equal [], d.logs.grep(/\[error\]/)
    end

    # v1.0.0 did not know record_accessor, so these keys were top-level keys
    # there, and Fluentd started. master stops at start for them, and so does
    # this version, so that a typo does not leave a nested value unmasked.
    data("a space" => "$.user name", "an open bracket" => "$[foo", "a bracket without quotes" => "$.a[x]",
         "a bracket after a dot" => "$.a['b']", "more after a bracket" => "$['a'].b")
    test "keys that record_accessor cannot read stops at start" do |key|
      e = assert_raise(Fluent::ConfigError) { create_driver("<mask sha1>\n  keys #{key}\n  salt s\n</mask>") }
      assert_include e.message, "#{key.inspect} in keys of <mask sha1> is not in the syntax of record_accessor"
      assert_include e.message, "$.user.name"
      assert_not_include e.message, "keys splits"
    end

    data("two keys" => ["$['a,b']", %q(keys ["$['a,b']"])],
         "three keys" => ["$['a,b,c'], d", %q(keys ["$['a,b,c']"])])
    test "keys with a comma in brackets stops at start, and shows a JSON array" do |(keys, hint)|
      e = assert_raise(Fluent::ConfigError) { create_driver("<mask sha1>\n  keys #{keys}\n  salt s\n</mask>") }
      assert_include e.message, %q("$['a" in keys of <mask sha1> is not in the syntax of record_accessor)
      assert_include e.message, hint
    end

    test "keys with a comma in brackets works as a JSON array" do
      d = create_driver(%Q(<mask sha1>\n  keys ["$['a,b']"]\n  salt s\n</mask>))
      d.run(default_tag: 'test') { d.feed(@time, {"a,b" => "alice", "a" => "x"}) }
      sha1 = OpenSSL::Digest.new("sha1").update("s").update("alice").hexdigest
      assert_equal [{"a,b" => sha1, "a" => "x"}], d.filtered_records
    end

    # record_accessor reads these keys as a path that is not what the key
    # shows: [0], ["", "a"], ["a"] and ["a", "", "b"].
    data("an index" => ["$[0]", "its first key is not a key of the record"],
         "an index after a dot" => ["$.[0]", nil],
         "two dots" => ["$..a", "it has an empty key"],
         "two dots inside" => ["$.a..b", "it has an empty key"],
         "a dot at the end" => ["$.a.", "it ends with a dot"])
    test "keys that record_accessor reads as another path stops at start" do |(key, problem)|
      e = assert_raise(Fluent::ConfigError) { create_driver("<mask sha1>\n  keys #{key}\n  salt s\n</mask>") }
      assert_include e.message, "#{key.inspect} in keys of <mask sha1>"
      assert_include e.message, problem if problem
    end

    test "keys with an empty key in brackets is the key \"\"" do
      d = create_driver("<mask sha1>\n  keys $[''], $['a']['']\n  salt s\n</mask>")
      d.run(default_tag: 'test') { d.feed(@time, {"" => "alice", "a" => {"" => "bob", "b" => "x"}}) }
      sha1 = ->(v) { OpenSSL::Digest.new("sha1").update("s").update(v).hexdigest }
      assert_equal [{"" => sha1.("alice"), "a" => {"" => sha1.("bob"), "b" => "x"}}], d.filtered_records
      assert_equal [], d.logs.grep(/\[(warn|error)\]/)
    end

    # master and 1.1.0 read such a key as a nested key.
    data("a dot" => ["user.name", "write $.user.name."],
         "$ without a dot" => ["$user.name", "write it as $.user.name."],
         "a dot at the start" => [".name", "write it as $.user.name."])
    test "keys with a dot that is not of record_accessor warns at start, and is a top-level key" do |(key, example)|
      d = create_driver("<mask sha1>\n  keys #{key}, other\n  salt s\n</mask>")
      d.run(default_tag: 'test') { d.feed(@time, {key => "flat", "user" => {"name" => "bob"}}) }
      sha1 = OpenSSL::Digest.new("sha1").update("s").update("flat").hexdigest
      assert_equal [{key => sha1, "user" => {"name" => "bob"}}], d.filtered_records
      warnings = d.logs.grep(/\[warn\]/)
      assert_equal 1, warnings.size, d.logs.join
      assert_include warnings.first, "#{key.inspect} in keys of <mask sha1> is the top-level key #{key.inspect}"
      assert_include warnings.first, example
    end

    test "keys without a dot or with record_accessor does not warn" do
      d = create_driver("<mask sha1>\n  keys user, $.user.name, $['user.name']\n  salt s\n</mask>")
      assert_equal [], d.logs.grep(/\[warn\]/)
    end

    test "keys that are the same key warns at start, and masks the value for each" do
      d = create_driver("<mask sha1>\n  keys a, $.a, $['a'], b, $.c.d, $['c']['d']\n  salt s\n</mask>")
      d.run(default_tag: 'test') { d.feed(@time, {"a" => "alice", "b" => "bob", "c" => {"d" => "carol"}}) }
      sha1 = ->(v) { OpenSSL::Digest.new("sha1").update("s").update(v).hexdigest }
      assert_equal [{"a" => sha1.(sha1.(sha1.("alice"))), "b" => sha1.("bob"), "c" => {"d" => sha1.(sha1.("carol"))}}], d.filtered_records
      warnings = d.logs.grep(/\[warn\]/)
      assert_equal 2, warnings.size, d.logs.join
      assert_include warnings[0], %q("a" and "$.a" and "$['a']" in keys of <mask sha1> are the same key, so its value is masked 3 times)
      assert_include warnings[1], %q("$.c.d" and "$['c']['d']" in keys of <mask sha1> are the same key, so its value is masked 2 times)
    end

    test "the same key twice warns too, as it is masked twice as in master" do
      d = create_driver("<mask sha1>\n  keys a, a\n  salt s\n</mask>")
      assert_equal 1, d.logs.grep(/\[warn\]: "a" and "a" in keys of <mask sha1> are the same key/).size, d.logs.join
    end

    test "the same key in two <mask> sections does not warn" do
      d = create_driver("<mask sha1>\n  keys a\n  salt s\n</mask>\n<mask md5>\n  keys $.a\n  salt s\n</mask>")
      assert_equal [], d.logs.grep(/\[warn\]/)
    end

    data("key_chain" => "key_chain a.b", "key_chains" => "key_chains a.b")
    test "key_chain and key_chains point to keys with $." do |param|
      e = assert_raise(Fluent::ObsoletedParameterError) { create_driver("<mask sha1>\n  #{param}\n  salt s\n</mask>") }
      assert_include e.message, "Use keys parameter instead, with $. for a nested key, such as $.user.name."
    end

    test "keys skips null, as v1.0.0" do
      d = create_driver("<mask sha1>\n  keys [null, \"a\"]\n  salt s\n</mask>")
      d.run(default_tag: 'test') { d.feed(@time, {nil => "x", "a" => "alice"}) }
      sha1 = OpenSSL::Digest.new("sha1").update("s").update("alice").hexdigest
      assert_equal [{nil => "x", "a" => sha1}], d.filtered_records
    end

    test "keys with an Array is the top-level key of the Array, as v1.0.0" do
      d = create_driver("<mask sha1>\n  keys [[\"user\", \"name\"]]\n  salt s\n</mask>")
      d.run(default_tag: 'test') { d.feed(@time, {["user", "name"] => "alice", "user" => {"name" => "bob"}}) }
      sha1 = OpenSSL::Digest.new("sha1").update("s").update("alice").hexdigest
      assert_equal [{["user", "name"] => sha1, "user" => {"name" => "bob"}}], d.filtered_records
    end
  end
end

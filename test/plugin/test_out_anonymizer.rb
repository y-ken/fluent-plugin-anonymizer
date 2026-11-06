require 'helper'
require 'fluent/test/driver/output'
require 'fluent/plugin/out_anonymizer'

class AnonymizerOutputTest < Test::Unit::TestCase
  def setup
    Fluent::Test.setup
    @time = Fluent::EventTime.now
  end

  def create_driver(conf)
    Fluent::Test::Driver::Output.new(Fluent::Plugin::AnonymizerOutput).configure(conf)
  end

  def emit(conf, records, tag: 'input.access')
    d = create_driver(conf)
    d.run(default_tag: tag) { records.each { |r| d.feed(@time, Marshal.load(Marshal.dump(r))) } }
    d
  end

  def sha1(salt, value)
    OpenSSL::Digest.new("sha1").update(salt).update(value).hexdigest
  end

  # Each expected tag and record is the output of fluent-plugin-anonymizer
  # 1.0.0 on Ruby 2.7 for INPUT with the tag input.access. A record holds only
  # the top-level keys that v1.0.0 changed.
  INPUT = {
    "host" => "10.102.3.80", "host6" => "2001:db8:0:8d3:0:8a2e:70:7344", "mapped" => "::ffff:129.144.52.38",
    "not_ip" => "localhost", "ips" => ["10.1.2.3", "2001:db8::1"], "user_id" => "alice", "member_id" => "12345",
    "mail" => "example@example.com", "num" => 42, "null" => nil, "false" => false, "empty" => "",
    "list" => ["1000", "2000"], "hash" => {"k" => "v"}, "user.name" => "flat", "user id" => "spaced",
    "nest" => {"id" => "42", "ip" => "192.168.1.10", "null" => nil, "deep" => {"id" => "7"}},
  }
  V1_CONFIGS = {
    "README of v1.0.0" => [
      "sha1_keys user_id, member_id, mail\nhash_salt mysaltstring\nipaddr_mask_keys host, host6\nipv4_mask_subnet 24\nipv6_mask_subnet 104\ntag anonymized.${tag}\nremove_tag_prefix input.",
      "anonymized.access",
      {"host"=>"10.102.3.0", "host6"=>"2001:db8:0:8d3:0:8a2e::", "user_id"=>"1feb6da4f401a00d5f2daad4264e3e7ed76cb10b", "member_id"=>"5ab2cebb0537866c4a0cd2e2f3502c0976b788da", "mail"=>"7e9d6dbefa72d56056c8c740b34b5c0bbfec8d87"},
    ],
    "all methods" => [
      "md5_keys user_id, null\nsha1_keys member_id, nest.id\nsha256_keys mail, list\nsha384_keys num\nsha512_keys false, nest.deep.id, nest.missing\nhash_salt s\nipaddr_mask_keys host, host6, mapped, not_ip, ips, nest.ip\nremove_tag_prefix input.\nadd_tag_prefix anonymized.",
      "anonymized.access",
      {"host"=>"10.102.3.0", "host6"=>"2001:db8:0:8d3:0:8a2e::", "mapped"=>"::ffff:129.0.0.0", "ips"=>["10.1.2.0", "2001:db8::"], "user_id"=>"96f00994e47070f3462c11221ea6453d", "member_id"=>"5dd5d5d89d592e2624b117f9a169e4ea36e7e416", "mail"=>"eb13eea2534a5bce279ecd282342ef33d75d9f5e38fa9351f7087dca39807338", "num"=>"0f2880910fee4fec5a254c13eea6d18a3aa0a4b7a51d8877a285181741c2fb357165fd744b8c11971bf83dc07931418d", "null"=>"03c7c0ace395d80182db07ae2c30f034", "false"=>"b8db8839812155baa18f4713a0a1dc57107b06b158eec34c16c6674ec7ac2e5c3b9e1fa1d8344ff42c70baf1153488f93c8140ad0f85e6816840a6f96d8cf724", "list"=>["f473201a124ba394cf2a1ece4f7d9a805784f362fad7858e7710b4270ca7d36f", "5935722e3041d671a73e388dba6aeeac33079076d15e89d1b3aaa259a976f0ea"], "nest"=>{"id"=>"f385cb9f3a25fd64b6fc0961aff333e0e45f3385", "ip"=>"192.168.1.0", "null"=>nil, "deep"=>{"id"=>"afe5d892729af8e02a42e4d8523a15d55c419d26add97c0148e1285215504520b0d668b81a7ea839721accfcb8095749199e57309b4e799f5716bb7178b60e6e"}}},
    ],
    "without hash_salt" => [
      "sha1_keys user_id\nadd_tag_prefix x.",
      "x.input.access",
      {"user_id"=>"522b276a356bdf39013dfabea2cd43e141ecc9e8"},
    ],
    "subnets and remove_tag_suffix" => [
      "ipaddr_mask_keys host, host6\nipv4_mask_subnet 8\nipv6_mask_subnet 48\nremove_tag_suffix .access",
      "input",
      {"host"=>"10.0.0.0", "host6"=>"2001:db8::"},
    ],
    # Only the last method for a key, at the place of the first one.
    "same key in two parameters" => [
      "sha1_keys user_id, mail\nmd5_keys user_id\nsha256_keys mail\nhash_salt s\nadd_tag_suffix .x",
      "input.access.x",
      {"user_id"=>"96f00994e47070f3462c11221ea6453d", "mail"=>"eb13eea2534a5bce279ecd282342ef33d75d9f5e38fa9351f7087dca39807338"},
    ],
    # v1.0.0 removes the spaces in the keys, so "user id" becomes "userid".
    "key with a space" => [
      "sha1_keys user id, member_id\nhash_salt s\nadd_tag_prefix x.",
      "x.input.access",
      {"member_id"=>"5dd5d5d89d592e2624b117f9a169e4ea36e7e416"},
    ],
    "tag placeholders" => [
      "sha1_keys user_id\ntag a.__TAG__.${tag_parts[0]}.__TAG_PARTS[1]__.${tag_parts[-1]}.${tag_parts[0..1]}.__TAG_PARTS[0...1]__",
      "a.input.access.input.access.access.input.access.input",
      {"user_id"=>"522b276a356bdf39013dfabea2cd43e141ecc9e8"},
    ],
    "tag after the other tag options" => [
      "sha1_keys user_id\ntag anonymized.${tag}\nremove_tag_prefix input.\nadd_tag_suffix .z",
      "anonymized.access.z",
      {"user_id"=>"522b276a356bdf39013dfabea2cd43e141ecc9e8"},
    ],
    "add_tag_prefix without a dot" => [
      "sha1_keys user_id\nadd_tag_prefix anon",
      "anoninput.access",
      {"user_id"=>"522b276a356bdf39013dfabea2cd43e141ecc9e8"},
    ],
    "all tag options" => [
      "sha1_keys user_id\nremove_tag_prefix input.\nadd_tag_prefix anonymized.\nremove_tag_suffix .access\nadd_tag_suffix .done",
      "anonymized.access.done",
      {"user_id"=>"522b276a356bdf39013dfabea2cd43e141ecc9e8"},
    ],
    "remove_tag_prefix that does not match" => [
      "sha1_keys user_id\nremove_tag_prefix in.ut.",
      "input.access",
      {"user_id"=>"522b276a356bdf39013dfabea2cd43e141ecc9e8"},
    ],
    "include_tag_key" => [
      "sha1_keys user_id\nadd_tag_prefix x.\ninclude_tag_key true",
      "x.input.access",
      {"user_id"=>"522b276a356bdf39013dfabea2cd43e141ecc9e8", "tag"=>"x.input.access"},
    ],
    # The tag is set after masking.
    "tag_key" => [
      "sha1_keys user_id\nadd_tag_prefix x.\ninclude_tag_key true\ntag_key user_id",
      "x.input.access",
      {"user_id"=>"x.input.access"},
    ],
    "tag_key without include_tag_key" => [
      "sha1_keys user_id\nadd_tag_prefix x.\ntag_key orig",
      "x.input.access",
      {"user_id"=>"522b276a356bdf39013dfabea2cd43e141ecc9e8"},
    ],
  }

  data(V1_CONFIGS)
  test "outputs the same tag and record as v1.0.0" do |(conf, tag, changed)|
    d = emit(conf, [INPUT])
    assert_equal [[tag, INPUT.merge(changed)]], d.events.map { |t, _, r| [t, r] }
    assert_equal [], d.logs.grep(/\[error\]/)
  end

  data(V1_CONFIGS)
  test "warns once that out_anonymizer is deprecated" do |(conf, _, _)|
    d = create_driver(conf)
    assert_equal 1, d.logs.grep(/out_anonymizer is deprecated/).size, d.logs.inspect
    assert_equal [], d.logs.grep(/Error/), "the compat check reads a word Error as a failure"
  end

  data("no tag option" => ["sha1_keys user_id", "anonymizer: missing remove_tag_prefix, remove_tag_suffix, add_tag_prefix or add_tag_suffix."],
       "no keys" => ["hash_salt s\nadd_tag_prefix x.", "anonymizer: missing hash keys setting."],
       "unknown keys" => ["foo_keys user_id\nadd_tag_prefix x.", "anonymizer: unsupported key foo"])
  test "raises the same ConfigError as v1.0.0" do |(conf, message)|
    assert_raise(Fluent::ConfigError.new(message)) { create_driver(conf) }
  end

  test "keeps the time of each event" do
    d = create_driver("sha1_keys user_id\nadd_tag_prefix x.")
    t1 = Fluent::EventTime.new(1000)
    t2 = Fluent::EventTime.new(2000)
    d.run(default_tag: 'a') do
      d.feed(t1, {"user_id" => "alice"})
      d.feed(t2, {"user_id" => "bob"})
    end
    assert_equal [["x.a", t1, {"user_id" => sha1("", "alice")}], ["x.a", t2, {"user_id" => sha1("", "bob")}]], d.events
  end

  test "masks the records of a MessagePackEventStream" do
    d = create_driver("sha1_keys user_id\nadd_tag_prefix x.")
    es = Fluent::MultiEventStream.new
    es.add(@time, {"user_id" => "alice"})
    es.add(@time, {"user_id" => "bob"})
    d.run(default_tag: 'a') { d.feed('a', Fluent::MessagePackEventStream.new(es.to_msgpack_stream)) }
    assert_equal [{"user_id" => sha1("", "alice")}, {"user_id" => sha1("", "bob")}], d.events.map(&:last)
  end

  test "${hostname} and __HOSTNAME__ are the host name" do
    d = emit("sha1_keys user_id\ntag ${hostname}.__HOSTNAME__", [{"user_id" => "alice"}])
    host = Socket.gethostname
    assert_equal ["#{host}.#{host}"], d.events.map(&:first)
  end

  test "is ready for multiple workers" do
    assert_true create_driver("sha1_keys user_id\nadd_tag_prefix x.").instance.multi_workers_ready?
  end

  # v1.0.0 raised an error for these and emitted nothing.
  sub_test_case "where v1.0.0 emitted no event" do
    test "a path through a value that is not a Hash leaves the value as it is" do
      d = emit("sha1_keys user_id.x, user_id, nest.id.x\nadd_tag_prefix x.", [{"user_id" => "alice", "nest" => {"id" => "42"}}])
      assert_equal [{"user_id" => sha1("", "alice"), "nest" => {"id" => "42"}}], d.events.map(&:last)
      assert_equal [], d.logs.grep(/\[error\]/)
    end

    test "a part of the tag that does not exist becomes empty" do
      d = emit("sha1_keys user_id\ntag x.${tag_parts[5]}", [{"user_id" => "alice"}])
      assert_equal ["x."], d.events.map(&:first)
      assert_equal 1, d.logs.grep(/\[warn\]: .*tag_parts\[5\]/).size, d.logs.inspect
    end

    test "a part of the tag that does not exist warns once for each tag, not for each event stream" do
      d = create_driver("sha1_keys user_id\ntag x.${tag_parts[5]}")
      d.run(default_tag: 'input.access') do
        5.times { d.feed(@time, {"user_id" => "alice"}) }
        d.feed([[@time, {"user_id" => "bob"}], [@time, {"user_id" => "carol"}]])
        d.feed("input.other", @time, {"user_id" => "dave"})
      end
      assert_equal ["x."] * 8, d.events.map(&:first)
      warnings = d.logs.grep(/\[warn\]: .*tag_parts\[5\]/)
      assert_equal 2, warnings.size, d.logs.inspect
      assert_equal 1, warnings.grep(/'input\.access'/).size
      assert_equal 1, warnings.grep(/'input\.other'/).size
    end
  end

  # v1.0.0 left the whole Array as it was when an element is not an IP address.
  test "masks each IP address in an Array, and leaves an element that is not one" do
    d = emit("ipaddr_mask_keys ips\nadd_tag_prefix x.", [{"ips" => ["10.1.2.3", "bad", "2001:db8::1"]}])
    assert_equal [{"ips" => ["10.1.2.0", "bad", "2001:db8::"]}], d.events.map(&:last)
  end

  test "hash_salt is hidden in the configuration that Fluentd logs" do
    d = create_driver("sha1_keys data\nhash_salt hash_salt_string\nadd_tag_prefix anonymized.")
    assert_not_match(/hash_salt_string/, d.instance.config.to_s)
    assert_equal("hash_salt_string", d.instance.hash_salt)
  end
end

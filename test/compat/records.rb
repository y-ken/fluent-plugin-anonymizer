# frozen_string_literal: false
#
# The records that ci/check_config_compat.rb feeds to each configuration in
# test/compat/configs, through test/compat/plugin/in_compat_records.rb. This
# file is Ruby, so that a record can have what JSON cannot write: a String in
# ASCII-8BIT (as in_tail emits it without the encoding parameter) and a String
# that is not valid UTF-8. The last expression is an Array of records.
#
# Every record uses the same keys, so that each configuration masks something
# in each record. Add a record for each kind of value that a change may mask
# differently.
#
# base returns a new Hash with new values each time, so that no record shares
# a Hash, an Array or a String with another record. v1.0.0 writes the masked
# values into the record that it gets, so a shared object would carry a value
# that an earlier record changed into a later record.

base = lambda do
  {
    "host" => "10.102.3.80", "host6" => "2001:db8:0:8d3:0:8a2e:70:7344",
    "mapped" => "::ffff:129.144.52.38", "not_ip" => "localhost",
    "ips" => ["10.1.2.3", "2001:db8::1"], "user_id" => "alice", "session_id" => "sess-secret",
    "member_id" => "12345", "mail" => "example@example.com", "tel" => "00-0000-0000",
    "card" => "4111111111111111", "num" => 42, "null" => nil, "false" => false,
    "list" => ["1000", "2000"], "user.name" => "flat", "user" => "alice",
    "name" => "Tanaka", "url" => "http://user:pw@example.com/p?token=SECRET#f",
    "nest" => {"ip" => "192.168.1.10", "id" => "42", "name" => "bob", "null" => nil, "deep" => {"id" => "7"}},
  }
end

[
  # The sample of the configurations before this file.
  base.call,

  # Values of each type in each key.
  base.call.merge(
    "host" => nil, "host6" => false, "mapped" => true, "not_ip" => 12345, "ips" => [],
    "user_id" => nil, "session_id" => false, "member_id" => 12345, "mail" => 1.5,
    "tel" => [], "card" => {}, "num" => -1, "null" => "null", "false" => "false",
    "list" => [nil, false, 1, ["x"], {"a" => "b"}], "user.name" => nil,
    "user" => {"name" => "bob"}, "name" => nil, "url" => 1,
    "nest" => "not a Hash",
  ),
  base.call.merge(
    "user_id" => ["alice", "bob"], "mail" => {"a" => "b@example.com"},
    "nest" => {"ip" => ["192.168.1.10", "x"], "id" => nil, "deep" => []},
  ),

  # ASCII-8BIT, as in_tail emits.
  base.call.merge(
    "host" => "10.1.2.3".b, "host6" => "2001:db8::1".b, "user_id" => "alice".b,
    "mail" => "jose@mydomain".b, "name" => "田中太郎".b, "url" => "/reset?token=SECRET".b,
    "nest" => {"ip" => "192.168.1.10".b, "id" => "42".b},
    "名前".b => "田中太郎".b, "mail2".b => "jose@mydomain".b,
  ),

  # Not valid UTF-8.
  base.call.merge(
    "user_id" => "Jos\xE9", "mail" => "Jos\xE9 <jose@mydomain>", "name" => "\xE7\x94\xB0\xE4\xB8\xAD\xFF",
    "host" => "10.1.2.3\xFF", "url" => "http://example.com/\xFF?token=SECRET",
    "mail\xFF" => "jose@mydomain", "\xFF" => "jose@mydomain", "zz" => "jose@mydomain",
  ),

  # Addresses.
  base.call.merge(
    "host" => "::ffff:10.1.2.3", "host6" => "2001:0db8:0000::0001", "mapped" => "::FFFF:192.168.1.1",
    "not_ip" => "10.1.2.3:8080", "ips" => ["10.1.2.3", nil, "x", ["10.9.9.9"]],
    "user_id" => "192.168.1.1", "mail" => "::ffff:192.168.1.1", "member_id" => "10.1.2.3/24",
    "nest" => {"ip" => "1.2.3.4, 10.0.0.1", "id" => "fe80::1%eth0"},
  ),

  # URIs.
  base.call.merge(
    "url" => "/reset?token=SECRET&email=a@b.c", "user_id" => "//ex.com/p?token=SECRET",
    "mail" => "mailto:alice@example.com", "member_id" => "http://ex.com/a b?email=a@b.c",
    "name" => "http://ex.com/ü?email=a@b.c", "tel" => "/p;jsessionid=SECRET?x=1",
    "list" => ["/a?x=1", "http://u:p@ex.com/b?y=2"], "card" => "/my/path",
  ),

  # Keys that select each salt of salts, and an empty key.
  base.call.merge(
    "" => "empty key", "a" => "a", "b" => "b", "c" => "c", "d" => "d", "id" => "id", "ab" => "ab",
  ),

  # A frozen Hash in a nested Hash. A mask that writes to it raises
  # FrozenError, and Fluentd outputs the record only if the mask rescues it,
  # as v1.0.0 does.
  base.call.merge(
    "nest" => {"ip" => "192.168.1.10", "id" => "42", "name" => "bob", "null" => nil, "deep" => {"id" => "7"}.freeze},
  ),
]

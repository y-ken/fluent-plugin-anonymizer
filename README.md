# fluent-plugin-anonymizer [![CI](https://github.com/y-ken/fluent-plugin-anonymizer/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/y-ken/fluent-plugin-anonymizer/actions/workflows/ci.yml)

## Overview

Fluentd filter plugin to anonymize records with [OpenSSL::Digest](https://docs.ruby-lang.org/ja/latest/class/OpenSSL=3a=3aDigest.html) of MD5/SHA1/SHA256/SHA384/SHA512 algorithms. This data masking plugin protects privacy data such as UserID, Email, Phone number, IPv4/IPv6 address and so on.

## Requirements

| fluent-plugin-anonymizer | fluentd    | ruby   |
|--------------------|------------|--------|
|  1.1.0            | v0.14.x | >= 2.7 |
|  1.0.0            | v0.14.x | >= 2.1 |
|  0.5.1            | v0.12.x | >= 1.9 |


## Installation

install with gem or td-agent-gem command as:

```
# for system installed fluentd
$ gem install fluent-plugin-anonymizer

# for td-agent2 (with fluentd v0.12)
$ sudo td-agent-gem install fluent-plugin-anonymizer -v 0.5.1

# for td-agent3 (with fluentd v1.0)
$ sudo td-agent-gem install fluent-plugin-anonymizer -v 1.1.0
```

For more details, see [Plugin Management](https://docs.fluentd.org/v1.0/articles/plugin-management)

## Tutorial

### Filter Plugin

#### configuration

```text
<source>
  @type dummy
  tag raw.dummy
  dummy [
  {"host":"10.102.3.80","member_id":"12345", "mail":"example@example.com"},
  {"host":"2001:db8:0:8d3:0:8a2e::","member_id":"61f6c1b5f19e0a7f73dd52a23534085bf01f2c67","mail":"eeb890d74b8c1c4cd1e35a3ea62166e0b770f4f4"}
  ]
</source>

<filter raw.**>
  @type anonymizer

  # Specify hashing keys with comma
  <mask sha1>
    keys user_id, member_id, mail
    # Set hash salt with any strings for more security
    salt mysaltstring
  </mask>
  # Specify rounding address keys with comma and subnet mask
  <mask network>
    keys  host
    ipv4_mask_bits  24
    ipv6_mask_bits  104
  </mask>
</filter>

<match raw.**>
  @type stdout
</match>
 ```

#### result

This sample result has made with the above configuration into "fluent.conf".

```text
$ fluentd -c fluent.conf
2017-12-25 15:00:00.091048000 +0900 raw.dummy: {"host":"10.102.3.0","member_id":"5ab2cebb0537866c4a0cd2e2f3502c0976b788da","mail":"7e9d6dbefa72d56056c8c740b34b5c0bbfec8d87"}
2017-12-25 15:00:01.005351000 +0900 raw.dummy: {"host":"2001:db8:0:8d3:0:8a2e::","member_id":"445514dfcd82b2a8b94ec6763afa6e349e78c5f8","mail":"54608576c8d815a4ffd595a3c1fe72751ed04424"}
2017-12-25 15:00:02.024865000 +0900 raw.dummy: {"host":"10.102.3.0","member_id":"b14a8f98019ec84c6fe329d5af62c46bb45348f8","mail":"723da8084da3438d9287b44e5a714b70e10a9755"}
2017-12-25 15:00:03.053852000 +0900 raw.dummy: {"host":"2001:db8:0:8d3:0:8a2e::","member_id":"d38ebb9b96c0cbffd4136935c7f6fe9dd05980cd","mail":"b6f9d777831cbecfd2ea806f5f62f79a275bbb82"}
```

## Parameters

### mask section

Mask section will use following configuration syntax:

```aconf
<mask ARGUMENTS>
  PARAMETERS
</mask>
```

#### Parameters

* `arguments`
  * `md5`
  * `sha1`
  * `sha256`
  * `sha384`
  * `sha512`
  * `uri_path`
  * `network`

* `keys` (default: [])

Specify one or more keys that will be applied hash algorithm.
A key is a top-level key of the record, even if it has a dot: `user.name` is the key `"user.name"`.
For a nested key, use the syntax of [record_accessor](https://docs.fluentd.org/plugin-helper-overview/api-plugin-helper-record_accessor), such as `$.user.name` or `$['user']['name']`.
A key that starts with `$.` or `$[` but is not in that syntax, such as `$.user name`, or that record_accessor reads as another key, such as `$[0]`, `$..a` or `$.a.`, stops Fluentd with an error when it starts.
`keys` is split at each comma, so write a key with a comma as a JSON array, such as `keys ["$['a,b']"]`.
A key that exists is masked even if its value is `null` or `false`.

* `key_pattern` (default: nil)

Specify pattern of keys that will be applied hash algorithm.

* `value_pattern` (default: nil)

Specify pattern of value that will be applied hash algorithm.

* `value_in_subnet` (default: nil)

Specify network of value that will be applied hash algorithm.

* `salt` (default: none)

This salt affects for `keys` settings.
It is recommend to set a hash salt to prevent rainbow table attacks.

* `mask_array_elements` (default: false)

If true, mask all elements in the array that specified by keys or key_pattern.

* `ipv4_mask_bits` (default: nil)
* `ipv6_mask_bits` (default: nil)

Round number for following one or more keys. It makes easy to aggregate calculation.

| ipv4_mask_bits   |      input      |    output     |
|------------------|-----------------|---------------|
|               24 | 192.168.200.100 | 192.168.200.0 |
|               16 | 192.168.200.100 | 192.168.0.0   |
|                8 | 192.168.200.100 | 192.0.0.0     |


## Notes

* Hash and Array values on Ruby 3.4 and later

The hash methods and `value_pattern` read a value as a string with `to_s`. Ruby 3.4 changed `Hash#inspect`, which `to_s` uses, from `{"k"=>"v"}` to `{"k" => "v"}`. So on Ruby 3.4 and later, this plugin writes a plain Hash or Array in the format of Ruby 3.3 and earlier, such as `{"k"=>"v"}`. A plain value is a Hash or an Array that holds only plain Hashes and Arrays, strings, symbols, integers, floats, `nil`, `true` and `false`, with none of its classes or methods changed. Any other value uses `to_s` of the running Ruby, as before. For example, a Struct that holds a Hash is written in the format of the running Ruby.

On Ruby 3.4 and later, this changes the digest of a non-empty Hash value, and of an Array value that contains a non-empty Hash, from the one made by the previous version of this plugin. These values go back to the digest made on Ruby 3.3 and earlier.

A `value_pattern` written for the Ruby 3.4 format, such as `"k" => "v"`, no longer matches these values, so it no longer masks them. Change such a pattern to the format of Ruby 3.3 and earlier, such as `"k"=>"v"`.

Even for a plain value, a character inside a Hash or an Array may be written differently on another Ruby version, so its digest may change. For example, U+1FAE9 is written as `\u{1FAE9}` on Ruby 3.3 and 3.4, and as the character itself on Ruby 4.0. Ruby 4.0 writes many characters as they are, which Ruby 3.3 and 3.4 write as escapes.

* hashing nested value behavior is compatible with [LogStash::Filters::Anonymize](https://github.com/logstash-plugins/logstash-filter-anonymize/blob/master/lib/logstash/filters/anonymize.rb) does. For further details, please check it out the test code at [test_emit_nest_value](https://github.com/y-ken/fluent-plugin-anonymizer/blob/master/test/plugin/test_filter_anonymizer.rb#L231).

* How to reproduce anonymized string with another way?

You can reproduce same result with both ways.

```
<filter raw.**>
  @type anonymizer
  <mask sha512>
    keys email_for_sha512
    salt 
  </mask>
</filter>
```

```
$ echo -n "example@gmail.com" | openssl sha512
(stdin)= 7759b39ee43dda414560836863675714eb2040e8c305cb4180fc850937ccbfcfc0c2fcab65ca8509a861b1703a33678b330c418263e9a29f80747102f972cee0
```

## Blog Articles

* 個人情報を難読化するfluent-plugin-anonymizerをリリースしました #fluentd - Y-Ken Studio  
http://y-ken.hatenablog.com/entry/fluent-plugin-anonymizer-has-released

## TODO

Pull requests are very welcome!!

## Copyright

Copyright © 2013- Kentaro Yoshida ([@yoshi_ken](https://twitter.com/yoshi_ken))

## License

Apache License, Version 2.0

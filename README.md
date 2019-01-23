# fluent-plugin-anonymizer [![Build Status](https://travis-ci.org/y-ken/fluent-plugin-anonymizer.png?branch=master)](https://travis-ci.org/y-ken/fluent-plugin-anonymizer)

## Overview

Fluentd filter plugin to anonymize records with [OpenSSL::Digest](https://docs.ruby-lang.org/ja/latest/class/OpenSSL=3a=3aDigest.html) of MD5/SHA1/SHA256/SHA384/SHA512 algorithms. This data masking plugin protects privacy data such as UserID, Email, Phone number, IPv4/IPv6 address and so on.

## Requirements

| fluent-plugin-anonymizer | fluentd    | ruby   |
|--------------------|------------|--------|
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
$ sudo td-agent-gem install fluent-plugin-anonymizer -v 1.0.0
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
    ipv4_mask_subnet  24
    ipv6_mask_subnet  104
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

* hashing nested value behavior is compatible with [LogStash::Filters::Anonymize](https://github.com/logstash/logstash/blob/master/lib/logstash/filters/anonymize.rb) does. For further details, please check it out the test code at [test_emit_nest_value](https://github.com/y-ken/fluent-plugin-anonymizer/blob/master/test/plugin/test_filter_anonymizer.rb#L231).

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

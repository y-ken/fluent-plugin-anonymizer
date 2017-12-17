# fluent-plugin-anonymizer [![Build Status](https://travis-ci.org/y-ken/fluent-plugin-anonymizer.png?branch=master)](https://travis-ci.org/y-ken/fluent-plugin-anonymizer)

## Overview

Fluentd filter output plugin to anonymize records with [OpenSSL::Digest](https://docs.ruby-lang.org/ja/latest/class/OpenSSL=3a=3aDigest.html) of MD5/SHA1/SHA256/SHA384/SHA512 algorithms. This data masking plugin protects privacy data such as UserID, Email, Phone number, IPv4/IPv6 address and so on.

## Requirements

| fluent-plugin-anonymizer | fluentd    | ruby   |
|--------------------|------------|--------|
|  1.0.0            | v0.14.x | >= 2.1 |
|  0.5.1            | v0.12.x | >= 1.9 |


## Installation

install with gem or td-agent-gem command as:

`````
# for system installed fluentd
$ gem install fluent-plugin-anonymizer

# for td-agent2 (with fluentd v0.12)
$ sudo td-agent-gem install fluent-plugin-anonymizer -v 0.5.1

# for td-agent3 (with fluentd v0.14)
$ sudo td-agent-gem install fluent-plugin-anonymizer -v 1.0.0
`````

For more details, see [Plugin Management](https://docs.fluentd.org/v0.14/articles/plugin-management)

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
  sha1_keys         user_id, member_id, mail
  
  # Set hash salt with any strings for more security
  hash_salt         mysaltstring
  
  # Specify rounding address keys with comma and subnet mask
  ipaddr_mask_keys  host
  ipv4_mask_subnet  24
  ipv6_mask_subnet  104
</filter>

<match raw.**>
  @type stdout
</match>
 ```

#### result

This sample result has made with the above configuration into "fluent.conf".

```text
$ fluentd -c fluent.conf
2017-02-27 22:59:18.070132000 +0900 raw.dummy: {"host":"10.102.3.0","member_id":"5ab2cebb0537866c4a0cd2e2f3502c0976b788da","mail":"7e9d6dbefa72d56056c8c740b34b5c0bbfec8d87"}
2017-02-27 22:59:19.079251000 +0900 raw.dummy: {"host":"2001:db8:0:8d3:0:8a2e::","member_id":"445514dfcd82b2a8b94ec6763afa6e349e78c5f8","mail":"54608576c8d815a4ffd595a3c1fe72751ed04424"}
2017-02-27 22:59:20.086747000 +0900 raw.dummy: {"host":"10.102.3.0","member_id":"b14a8f98019ec84c6fe329d5af62c46bb45348f8","mail":"723da8084da3438d9287b44e5a714b70e10a9755"}
2017-02-27 22:59:21.094767000 +0900 raw.dummy: {"host":"2001:db8:0:8d3:0:8a2e::","member_id":"d38ebb9b96c0cbffd4136935c7f6fe9dd05980cd","mail":"b6f9d777831cbecfd2ea806f5f62f79a275bbb82"}
```

### Output Plugin

#### configuration

It is a sample to hash record with sha1 for `user_id`, `member_id` and `mail`. For IP address, auto-detecting IPv4/IPv6 and rounding number with 24bit(IPv4) or 104bit(IPv6) netmask using `ipaddr_mask_keys` and `ipv4_mask_subnet`, `ipv6_mask_subnet` option.

`````
<source>
  @type forward
  port 24224
</source>

<match test.message>
  @type anonymizer
  
  # Specify hashing keys with comma
  sha1_keys         user_id, member_id, mail
  
  # Set hash salt with any strings for more security
  hash_salt         mysaltstring
  
  # Specify rounding address keys with comma and subnet mask
  ipaddr_mask_keys  host
  ipv4_mask_subnet  24
  ipv6_mask_subnet  104
  
  # Set tag rename pattern
  tag               anonymized.${tag}
  remove_tag_prefix test.
</match>

<match anonymized.message>
  @type stdout
</match>
`````

#### result

`````
$ echo '{"host":"10.102.3.80","member_id":"12345", "mail":"example@example.com"}' | fluent-cat test.message
$ echo '{"host":"2001:db8:0:8d3:0:8a2e:70:7344","member_id":"12345", "mail":"example@example.com"}' | fluent-cat test.message

$ tail -f /var/log/td-agent/td-agent.log
2014-01-06 18:30:21 +0900 anonymized.message: {"host":"10.102.3.0","member_id":"61f6c1b5f19e0a7f73dd52a23534085bf01f2c67","mail":"eeb890d74b8c1c4cd1e35a3ea62166e0b770f4f4"}
2014-01-06 18:30:22 +0900 anonymized.message: {"host":"2001:db8:0:8d3:0:8a2e::","member_id":"61f6c1b5f19e0a7f73dd52a23534085bf01f2c67","mail":"eeb890d74b8c1c4cd1e35a3ea62166e0b770f4f4"}
`````

## Parameters

* `md5_keys` `sha1_keys` `sha256_keys` `sha384_keys` `sha512_keys`

Specify which hash algorithm to be used for following one or more keys.

* `hash_salt` (default: none)

This salt affects for `md5_keys` `sha1_keys` `sha256_keys` `sha384_keys` `sha512_keys` settings.  
It is recommend to set a hash salt to prevent rainbow table attacks.


* `ipaddr_mask_keys`
* `ipv4_mask_subnet` (default: 24)
* `ipv6_mask_subnet` (default: 104)

Round number for following one or more keys. It makes easy to aggregate calculation. 

| ipv4_mask_subnet |      input      |    output     |
|------------------|-----------------|---------------|
|               24 | 192.168.200.100 | 192.168.200.0 |
|               16 | 192.168.200.100 | 192.168.0.0   |
|                8 | 192.168.200.100 | 192.0.0.0     |

* include_tag_key (default: false)
* tag_key

set one or more option are required for editing tag name using HandleTagNameMixin.

* tag

In the case of using this option [like 'tag anonymized.${tag}' with tag placeholder](https://github.com/y-ken/fluent-plugin-anonymizer/blob/master/test/plugin/test_out_anonymizer.rb#L179), tag will be modified after these options affected. which are remove_tag_prefix, remove_tag_suffix, add_tag_prefix and add_tag_suffix.

Add original tag name into filtered record using SetTagKeyMixin.

* remove_tag_prefix
* remove_tag_suffix
* add_tag_prefix
* add_tag_suffix

## Notes

* hashing nested value behavior is compatible with [LogStash::Filters::Anonymize](https://github.com/logstash/logstash/blob/master/lib/logstash/filters/anonymize.rb) does. For further details, please check it out the test code at [test_emit_nest_value](https://github.com/y-ken/fluent-plugin-anonymizer/blob/master/test/plugin/test_out_anonymizer.rb#L91).

## Blog Articles

* 個人情報を難読化するfluent-plugin-anonymizerをリリースしました #fluentd - Y-Ken Studio  
http://y-ken.hatenablog.com/entry/fluent-plugin-anonymizer-has-released

## TODO

Pull requests are very welcome!!

## Copyright

Copyright © 2013- Kentaro Yoshida ([@yoshi_ken](https://twitter.com/yoshi_ken))

## License

Apache License, Version 2.0

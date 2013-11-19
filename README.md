# fluent-plugin-anonymizer

## Overview

Fluentd filter output plugin to anonymize records. This data masking plugin protects privacy data such as IP address, ID, email, phone number and so on.

## Installation

`````
### native gem
gem install fluent-plugin-anonymizer

### td-agent gem
/usr/lib64/fluent/ruby/bin/fluent-gem install fluent-plugin-anonymizer
`````

## Tutorial

#### configuration

It is a sample to hash record with sha1 for user_id, member_id, mail.

`````
<source>
  type forward
  port 24224
</source>

<match test.message>
  type anonymize
  sha1_keys         user_id, member_id, mail
  hash_salt         foobar
  ipv4_mask_keys    host
  ipv4_mask_subnet  24
  remove_tag_prefix test.
  add_rag_prefix    anonymized.
</match>

<match anonymized.message>
  type stdout
</match>
`````

#### result

`````
$ echo '{"host":"10.102.3.80","member_id":"12345", "mail":"example@example.com"}' | fluent-cat test.message

$ tail -f /var/log/td-agent/td-agent.log
2013-11-19 18:30:21 +0900 anonymized.message: {"host":"10.102.0.0","member_id":"8cb2237d0679ca88db6464eac60da96345513964","mail":"914fec35ce8bfa1a067581032f26b053591ee38a"}
`````

### Params

* `md5_keys` `sha1_keys` `sha256_keys` `sha384_keys` `sha512_keys`

Specify which hash algorithm to be used for following one or more keys.

* `hash_salt` (default: none)

This salt affects for `md5_keys` `sha1_keys` `sha256_keys` `sha384_keys` `sha512_keys` settings.  
It is recommend to set a hash salt to prevent rainbow table attacks.


* `ipv4_mask_keys`
* `ipv4_mask_subnet` (default: 24)

Round number for following one or more keys. It makes easy to aggregate calculation. 

| ipv4_mask_subnet |      input      |    output     |
|------------------|-----------------|---------------|
|               24 | 192.168.200.100 | 192.168.200.0 |
|               16 | 192.168.200.100 | 192.168.0.0   |
|                8 | 192.168.200.100 | 192.0.0.0     |

* include_tag_key (default: false)

Add original tag name into filtered record using SetTagKeyMixin function.

* remove_tag_prefix
* remove_tag_suffix
* add_tag_prefix
* add_tag_suffix

Edit tag format using HandleTagNameMixin function.

## Blog Articles

* http://y-ken.hatenablog.com/entry/fluent-plugin-anonymizer-has-released

## TODO

Pull requests are very welcome!!

## Copyright

Copyright © 2013- Kentaro Yoshida ([@yoshi_ken](https://twitter.com/yoshi_ken))

## License

Apache License, Version 2.0

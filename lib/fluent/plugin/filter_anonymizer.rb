require 'fluent/filter'
require 'openssl'
require 'uri'
require 'ipaddr'

# <filter **>
#   @type mask
#   # salts will be selected for field names in a deterministic way
#   salt secret_salt # different salt for each fields?
#   salt salt_brabra
#   salts s1,s2,s3,s4
#   <mask sha1>
#     # key user_id
#     keys ["user_id","session_id","source_ip"]
#     key_pattern   ^(source|src)_?ip_?(addr|address)?$
#     value_pattern   @mydomain\.example\.com$
#     value_in_subnet 192.168.0.0/16 # naming?
#   </mask>
#   <mask uri_path>
#     keys ["url","uri"]
#     # or key_pattern
#   </mask>
#   <mask network>
#     keys ["dest","destination","dest_ip"]
#     # or key_pattern
#     ipv4_mask_bits 24
#     ipv6_mask_bits 104
#   </mask>
# </filter>

module Fluent
  class AnonymizerFilter < Filter
    Fluent::Plugin.register_filter('anonymizer', self)

    MASK_METHODS = {
      md5:    ->(opts){ ->(v,salt){ OpenSSL::Digest.new("md5").update(salt).update(v.to_s).hexdigest } },
      sha1:   ->(opts){ ->(v,salt){ OpenSSL::Digest.new("sha1").update(salt).update(v.to_s).hexdigest } },
      sha256: ->(opts){ ->(v,salt){ OpenSSL::Digest.new("sha256").update(salt).update(v.to_s).hexdigest } },
      sha384: ->(opts){ ->(v,salt){ OpenSSL::Digest.new("sha384").update(salt).update(v.to_s).hexdigest } },
      sha512: ->(opts){ ->(v,salt){ OpenSSL::Digest.new("sha512").update(salt).update(v.to_s).hexdigest } },
      uri_path: ->(opts){ ->(v,salt){
          begin
            uri = URI.parse(v)
            if uri.absolute?
              uri.path = '/'
              uri.user = uri.password = uri.query = uri.fragment = nil
            end
            uri.to_s
          rescue
            v
          end
        } },
      network: ->(opts){ ->(v,salt){
          begin
            addr = IPAddr.new(v)
            if addr.ipv4? && opts.ipv4_mask_bits
              addr.mask(opts.ipv4_mask_bits).to_s
            elsif addr.ipv6? && opts.ipv6_mask_bits
              addr.mask(opts.ipv6_mask_bits).to_s
            else
              addr.to_s
            end
          rescue
            v
          end
        } },
    }

    config_param :salt, default: nil do |value|
      @salt_list << value.strip.to_s
    end
    config_param :salts, default: nil do |values|
      values.split(',').map(&:strip).each do |value|
        @salt_list << value
      end
    end
    config_section :mask, param_name: :mask_config_list, required: false, multi: true do
      config_argument :method, :enum, list: MASK_METHODS.keys
      config_param :salt, :string, default: nil

      config_param :key, :string, default: nil
      config_param :keys, :array, default: []
      config_param :key_pattern, :string, default: nil
      config_param :value_pattern, :string, default: nil
      config_param :value_in_subnet, :string, default: nil # 192.168.0.0/24

      config_param :ipv4_mask_bits, :integer, default: nil
      config_param :ipv6_mask_bits, :integer, default: nil
    end

    # obsolete configuration parameters
    config_param :md5_keys,    :string, default: nil
    config_param :sha1_keys,   :string, default: nil
    config_param :sha256_keys, :string, default: nil
    config_param :sha384_keys, :string, default: nil
    config_param :sha512_keys, :string, default: nil
    config_param :hash_salt,   :string, default: nil
    config_param :ipaddr_mask_keys, :string, default: nil
    config_param :ipv4_mask_subnet, :integer, default: 24
    config_param :ipv6_mask_subnet, :integer, default: 104

    def initialize
      super
      @salt_list = []
      @salt_map = {}
      @conversions = []
    end

    def configure(conf)
      super

      salt_missing = false

      @masks = []
      @mask_config_list.each do |c|
        unless c.salt || @salt_list.size > 0
          salt_missing = true
        end

        conv = MASK_METHODS[c.method].call(c)
        [c.key || nil, *c.keys].compact.each do |key|
          @masks << masker_for_key(conv, key, c.salt)
        end
        @masks << masker_for_key_pattern(conv, c.key_pattern, c.salt) if c.key_pattern
        @masks << masker_for_value_pattern(conv, c.value_pattern, c.salt) if c.value_pattern
        @masks << masker_for_value_in_subnet(conv, c.value_in_subnet, c.salt) if c.value_in_subnet
      end

      # obsolete option handling
      [[@md5_keys,:md5],[@sha1_keys,:sha1],[@sha256_keys,:sha256],[@sha384_keys,:sha384],[@sha512_keys,:sha512]].each do |param,m|
        next unless param
        @salt_list << (@hash_salt || '') if @salt_list.empty?
        conv = MASK_METHODS[m].call(OpenStruct.new)
        param.split(',').map(&:strip).each do |key|
          @masks << masker_for_key(conv, key, @hash_salt || '')
        end
      end
      if @ipaddr_mask_keys
        @salt_list << (@hash_salt || '') if @salt_list.empty?
        conf = OpenStruct.new
        conf.ipv4_mask_bits = @ipv4_mask_subnet
        conf.ipv6_mask_bits = @ipv6_mask_subnet
        conv = MASK_METHODS[:network].call(conf)
        @ipaddr_mask_keys.split(',').map(&:strip).each do |key|
          @masks << masker_for_key(conv, key, @hash_salt || '')
        end
      end

      if @masks.size < 1
        raise Fluent::ConfigError, "no anonymizing operations configured"
      end
      if salt_missing
        raise Fluent::ConfigError, "salt (or salts) required, but missing"
      end
    end

    def filter(tag, time, record)
      record.update(@masks.reduce(record){|r,mask| mask.call(r)})
    end

    def filter_stream(tag, es)
      new_es = MultiEventStream.new
      es.each do |time, record|
        new_es.add(time, @masks.reduce(record){|r,mask| mask.call(r) })
      end
      new_es
    end

    def salt_determine(key)
      return @salt_map[key] if @salt_map.has_key?(key)
      keystr = key.to_s
      if keystr.empty?
        @salt_map[key] = @salt_list[0]
      else
        @salt_map[key] = @salt_list[(keystr[0].ord + keystr[-1].ord) % @salt_map.size]
      end
      @salt_map[key]
    end

    def masker_for_key(conv, key, salt)
      ->(record){
        begin
          if record.has_key?(key)
            record[key] = conv.call(record[key], salt || salt_determine(key))
          end
        rescue => e
          log.error "unexpected error while masking value", error_class: e.class, error: e.message
        end
        record
      }
    end

    def masker_for_key_pattern(conv, pattern, salt)
      regexp = Regexp.new(pattern)
      -> (record){
        begin
          record.each_pair do |key, value|
            next unless (regexp =~ key.to_s rescue nil)
            record[key] = conv.call(value, salt || salt_determine(key))
          end
        rescue => e
          log.error "unexpected error while masking value", error_class: e.class, error: e.message
        end
        record
      }
    end

    def masker_for_value_pattern(conv, pattern, salt)
      regexp = Regexp.new(pattern)
      -> (record){
        begin
          record.each_pair do |key, value|
            next unless (regexp =~ value.to_s rescue nil)
            record[key] = conv.call(value, salt || salt_determine(key))
          end
        rescue => e
          log.error "unexpected error while masking value", error_class: e.class, error: e.message
        end
        record
      }
    end

    def masker_for_value_in_subnet(conv, network_str, salt)
      network = IPAddr.new(network_str)
      ->(record){
        begin
          record.each_pair do |key, value|
            next unless (network.include?(value) rescue nil)
            record[key] = conv.call(value, salt || salt_determine(key))
          end
        rescue => e
          log.error "unexpected error while masking value", error_class: e.class, error: e.message
        end
        record
      }
    end
  end
end

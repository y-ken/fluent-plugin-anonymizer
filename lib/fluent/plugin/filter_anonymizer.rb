require 'fluent/plugin/filter'
require 'openssl'
require 'uri'
require 'ipaddr'

# <filter **>
#   @type mask
#   # salts will be selected for field names in a deterministic way
#   salt secret_salt # different salt for each fields?
#   salt salt_brabra
#   salts ["s1","s2","s3","s4"]
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

module Fluent::Plugin
  class AnonymizerFilter < Filter
    Fluent::Plugin.register_filter('anonymizer', self)

    helpers :record_accessor

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

    OBSOLETED_MASK_METHOD_PARAMS_MESSAGE = <<EOF
Use
<mask MASK_METHOD>
  # ...
</mask>
instead.
EOF

    config_param :salt, :string, default: nil
    config_param :salts, :array, default: nil
    config_section :mask, param_name: :mask_config_list, required: true, multi: true do
      config_argument :method, :enum, list: MASK_METHODS.keys
      config_param :salt, :string, default: nil

      config_param :key,             :string, default: nil,
                   obsoleted: "Use keys parameter instead."
      config_param :keys,            :array,  default: []
      config_param :key_chain,       :string, default: nil, # for.nested.key
                   obsoleted: "Use keys parameter instead."
      config_param :key_chains,      :array,  default: [],  # ["for.nested.key","can.be.specified","twice.or.more"]
                   obsoleted: "Use keys parameter instead."
      config_param :key_pattern,     :string, default: nil
      config_param :value_pattern,   :string, default: nil
      config_param :value_in_subnet, :string, default: nil # 192.168.0.0/24

      config_param :mask_array_elements, :bool, default: false
      config_param :ipv4_mask_bits, :integer, default: nil
      config_param :ipv6_mask_bits, :integer, default: nil
    end

    # obsolete configuration parameters
    config_param :md5_keys,    :string, default: nil,
                 obsoleted: OBSOLETED_MASK_METHOD_PARAMS_MESSAGE
    config_param :sha1_keys,   :string, default: nil,
                 obsoleted: OBSOLETED_MASK_METHOD_PARAMS_MESSAGE
    config_param :sha256_keys, :string, default: nil,
                 obsoleted: OBSOLETED_MASK_METHOD_PARAMS_MESSAGE
    config_param :sha384_keys, :string, default: nil,
                 obsoleted: OBSOLETED_MASK_METHOD_PARAMS_MESSAGE
    config_param :sha512_keys, :string, default: nil,
                 obsoleted: OBSOLETED_MASK_METHOD_PARAMS_MESSAGE
    config_param :hash_salt,   :string, default: nil,
                 obsoleted: "Use salt parameter in mask directive instead."
    config_param :ipaddr_mask_keys, :string, default: nil,
                 obsoleted: "Use keys parameter in mask directive instead."
    config_param :ipv4_mask_subnet, :integer, default: 24,
                 obsoleted: "Use ipv4_mask_bits in mask directive instead."
    config_param :ipv6_mask_subnet, :integer, default: 104,
                 obsoleted: "Use ipv6_mask_bits in mask directive instead."

    def initialize
      super
      @salt_list = []
      @salt_map = {}
      @conversions = []
    end

    def configure(conf)
      super

      salt_missing = false

      @salt_list << @salt
      @salt_list += @salts if @salts

      @masks = []
      @mask_config_list.each do |c|
        unless c.salt || @salt_list.size > 0
          salt_missing = true
        end

        conv = MASK_METHODS[c.method].call(c)
        [*c.keys].compact.each do |key|
          key = convert_compat_key(key)
          if mask_with_key_chain?(key)
            @masks << masker_for_key_chain(conv, key, c)
          else
            @masks << masker_for_key(conv, key, c)
          end
        end
        @masks << masker_for_key_pattern(conv, c.key_pattern, c) if c.key_pattern
        @masks << masker_for_value_pattern(conv, c.value_pattern, c) if c.value_pattern
        @masks << masker_for_value_in_subnet(conv, c.value_in_subnet, c) if c.value_in_subnet
      end

      if @ipaddr_mask_keys
        @salt_list << (@hash_salt || '') if @salt_list.empty? # to suppress ConfigError for salt missing
        conf = OpenStruct.new
        conf.salt = @hash_salt || ''
        conf.mask_array_elements = true
        conf.ipv4_mask_bits = @ipv4_mask_subnet
        conf.ipv6_mask_bits = @ipv6_mask_subnet
        conv = MASK_METHODS[:network].call(conf)
        @ipaddr_mask_keys.split(',').map(&:strip).each do |key|
          key = convert_compat_key(key)
          if mask_with_key_chain?(key)
            @masks << masker_for_key_chain(conv, key, conf)
          else
            @masks << masker_for_key(conv, key, conf)
          end
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

    def convert_compat_key(key)
      if key.include?('.') && !key.start_with?('$[')
        key = "$.#{key}" unless key.start_with?('$.')
      end
      key
    end

    def mask_with_key_chain?(key)
      key.include?('.') || key.start_with?('$[') || key.start_with?('$.')
    end

    def salt_determine(key)
      return @salt_map[key] if @salt_map.has_key?(key)
      keystr = key.to_s
      if keystr.empty?
        @salt_map[key] = @salt_list[0]
      else
        @salt_map[key] = @salt_list[(keystr[0].ord + keystr[-1].ord) % @salt_list.size]
      end
      @salt_map[key]
    end

    def mask_value(value, for_each)
      if for_each && value.is_a?(Array)
        value.map{|v|
          yield v
        }
      else
        yield value
      end
    end

    def masker_for_key(conv, key, opts)
      for_each = opts.mask_array_elements
      salt = opts.salt || salt_determine(key)
      accessor = record_accessor_create(key)
      if for_each
        ->(record){
          begin
            if raw_value = accessor.call(record)
              record[key] = mask_value(raw_value, for_each){|v| conv.call(v, salt) }
            end
          rescue => e
            log.error "unexpected error while masking value", error_class: e.class, error: e.message
          end
          record
        }
      else
        ->(record){
          begin
            if raw_value = accessor.call(record)
              record[key] = conv.call(raw_value, salt)
            end
          rescue => e
            log.error "unexpected error while masking value", error_class: e.class, error: e.message
          end
          record
        }
      end
    end

    def masker_for_key_chain(conv, key, opts)
      for_each = opts.mask_array_elements
      accessor = record_accessor_create(key)
      ->(record){
        begin
          raw_value = accessor.call(record)
          keys = accessor.instance_variable_get(:@keys)
          heading = keys[0..-2]
          container = record.dig(*heading)
          tailing = keys.last
          if raw_value
            container[tailing] = mask_value(raw_value, for_each){|v| conv.call(v, opts.salt || salt_determine(tailing)) }
          end
        rescue => e
          log.error "unexpected error while masking value", error_class: e.class, error: e.message
        end
        record
      }
    end

    def masker_for_key_pattern(conv, pattern, opts)
      for_each = opts.mask_array_elements
      regexp = Regexp.new(pattern)
      ->(record){
        begin
          record.each_pair do |key, value|
            next unless (regexp =~ key.to_s rescue nil)
            record[key] = mask_value(record[key], for_each){|v| conv.call(v, opts.salt || salt_determine(key)) }
          end
        rescue => e
          log.error "unexpected error while masking value", error_class: e.class, error: e.message
        end
        record
      }
    end

    def masker_for_value_pattern(conv, pattern, opts)
      regexp = Regexp.new(pattern)
      ->(record){
        begin
          record.each_pair do |key, value|
            next unless (regexp =~ value.to_s rescue nil)
            record[key] = conv.call(value, opts.salt || salt_determine(key))
          end
        rescue => e
          log.error "unexpected error while masking value", error_class: e.class, error: e.message
        end
        record
      }
    end

    def masker_for_value_in_subnet(conv, network_str, opts)
      network = IPAddr.new(network_str)
      ->(record){
        begin
          record.each_pair do |key, value|
            next unless (network.include?(value) rescue nil)
            record[key] = conv.call(value, opts.salt || salt_determine(key))
          end
        rescue => e
          log.error "unexpected error while masking value", error_class: e.class, error: e.message
        end
        record
      }
    end
  end
end

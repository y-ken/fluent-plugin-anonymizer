require 'fluent/plugin/filter'
require 'fluent/plugin_helper/record_accessor'
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

    # Returns the string that a value is masked as, which is to_s of the value.
    # Ruby 3.4 changed Hash#inspect from {"a"=>1} to {"a" => 1}. So on Ruby 3.4
    # and later, a plain Hash or Array is written in the format before Ruby
    # 3.4, so that its digest does not change with the Ruby version. Any other
    # value uses to_s of the running Ruby, as before.
    def self.stringify(v)
      if OLD_FORMAT_NEEDED && (Hash === v || Array === v)
        s = inspect_before_ruby34(v)
        return s if s
      end
      v.to_s
    end

    OLD_FORMAT_NEEDED = Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("3.4")
    KERNEL_CLASS = Kernel.instance_method(:class)
    KERNEL_METHOD = Kernel.instance_method(:method)
    private_constant :OLD_FORMAT_NEEDED, :KERNEL_CLASS, :KERNEL_METHOD

    # Whether v is a Hash or an Array of the exact class that uses the
    # built-in method to write itself. It calls no method of v, which a
    # subclass could override or make private.
    def self.plain_container?(v, name)
      klass = KERNEL_CLASS.bind_call(v)
      return false unless klass.equal?(Hash) || klass.equal?(Array)
      KERNEL_METHOD.bind_call(v, name).owner.equal?(klass)
    rescue NameError # the method is undefined for v, which may use method_missing
      false
    end
    private_class_method :plain_container?

    # Writes value, a Hash or an Array, as inspect wrote it before Ruby 3.4.
    # Returns nil unless the value is plain: a Hash or an Array of the exact
    # class with the built-in to_s, which contains only Hashes and Arrays of
    # the exact class with the built-in inspect, Strings of the exact class,
    # Symbols, Integers, Floats, nil, true and false, and the inspect of each
    # of them is ASCII-only or in the default encoding, which Ruby does not
    # convert.
    #
    # It uses a stack instead of recursion, so that a deeply nested value does
    # not raise SystemStackError. Like inspect, it writes {...} or [...] for a
    # container that is already open on the current path (a cycle), and
    # writes a container that is shared but is not a cycle in full each time.
    def self.inspect_before_ruby34(value)
      return nil unless plain_container?(value, :to_s)
      encoding = Encoding.default_internal || Encoding.default_external
      encoding = nil unless encoding.ascii_compatible?
      buf = +""
      open = {}.compare_by_identity # the containers on the current path
      # 4 slots for each open container: the container, its keys or elements,
      # its values (nil for an Array), and the index of the next item. A Hash
      # has 2 items for each pair: the key and the value.
      stack = []
      v = value # a plain Hash or Array to write next
      while true
        hash = Hash === v
        if open.key?(v)
          buf << (hash ? "{...}" : "[...]")
        elsif v.empty?
          buf << (hash ? "{}" : "[]")
        else
          buf << (hash ? "{" : "[")
          open[v] = true
          stack.push(v, hash ? v.keys : v, hash ? v.values : nil, 0)
        end

        # Write the items of the innermost open container up to the next Hash
        # or Array, and close the containers that are done.
        v = nil
        until v || stack.empty?
          items, values, i = stack[-3], stack[-2], stack[-1]
          size = values ? items.size * 2 : items.size
          while i < size
            if values && i.odd?
              buf << "=>"
              x = values[i >> 1]
            else
              buf << ", " if i > 0
              x = values ? items[i >> 1] : items[i]
            end
            i += 1
            if Hash === x || Array === x
              return nil unless plain_container?(x, :inspect)
              v = x
              break
            end
            # No subclass of these classes, except String, can have an
            # instance, and none of them can have a singleton method.
            unless (String === x && KERNEL_CLASS.bind_call(x).equal?(String)) ||
                   Integer === x || Float === x || Symbol === x ||
                   nil.equal?(x) || true.equal?(x) || false.equal?(x)
              return nil
            end
            s = x.inspect
            return nil unless s.ascii_only? || s.encoding.equal?(encoding)
            buf << s
          end
          if v
            stack[-1] = i
          else
            buf << (values ? "}" : "]")
            stack.pop
            stack.pop
            stack.pop
            open.delete(stack.pop)
          end
        end
        return buf unless v
      end
    end
    private_class_method :inspect_before_ruby34

    MASK_METHODS = {
      md5:    ->(opts){ ->(v,salt){ OpenSSL::Digest.new("md5").update(salt).update(stringify(v)).hexdigest } },
      sha1:   ->(opts){ ->(v,salt){ OpenSSL::Digest.new("sha1").update(salt).update(stringify(v)).hexdigest } },
      sha256: ->(opts){ ->(v,salt){ OpenSSL::Digest.new("sha256").update(salt).update(stringify(v)).hexdigest } },
      sha384: ->(opts){ ->(v,salt){ OpenSSL::Digest.new("sha384").update(salt).update(stringify(v)).hexdigest } },
      sha512: ->(opts){ ->(v,salt){ OpenSSL::Digest.new("sha512").update(salt).update(stringify(v)).hexdigest } },
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
        # null in keys is skipped, as in v1.0.0.
        keys = c.keys.compact
        keys.each_with_index do |key, i|
          @masks << masker_for_key_chain(conv, key_path(key, keys[(i + 1)..-1], c), c)
        end
        @masks << masker_for_key_pattern(conv, c.key_pattern, c) if c.key_pattern
        @masks << masker_for_value_pattern(conv, c.value_pattern, c) if c.value_pattern
        @masks << masker_for_value_in_subnet(conv, c.value_in_subnet, c) if c.value_in_subnet
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

    NESTED_KEY_SYNTAX = "Write a nested key as $.user.name, or with brackets, such as $['user']['first name']."

    # Returns the path of a key in keys, an Array of keys: the keys of a key
    # that starts with $. or $[, in the syntax of record_accessor ($.a.b or
    # $['a']['b']), or the key itself for any other key, even if it has a dot
    # or is not a String, as in v1.0.0. rest is the keys after key in keys.
    #
    # A key that starts with $. or $[ but that record_accessor cannot read,
    # or reads as a path that is not what the key shows, such as $[0] (the
    # index 0) or $.a. (the key a), stops Fluentd at start, as master does
    # for most of them, so that a typo does not leave a nested value
    # unmasked. A key with a dot that does not start with $. or $[ is a
    # top-level key, as in v1.0.0, with a warning, because master read it as
    # a nested key.
    def key_path(key, rest, opts)
      return [key] unless key.is_a?(String)
      unless key.start_with?('$.', '$[')
        if key.include?('.')
          example = !key.start_with?('$') && parse_key("$.#{key}").first ? "$.#{key}" : 'it as $.user.name'
          log.warn "#{key.inspect} in keys of <mask #{opts.method}> is the top-level key #{key.inspect}, as in v1.0.0, " \
                   "though it has a dot. 1.1.0 read it as a nested key. For a nested key, write #{example}."
        end
        return [key]
      end
      path, error = parse_key(key)
      raise Fluent::ConfigError, "#{key.inspect} in keys of <mask #{opts.method}> #{error}#{comma_hint(key, rest)}" if error
      path
    end

    # Reads a key that starts with $. or $[ with record_accessor. Returns
    # [path, nil], or [nil, why the key is not read].
    def parse_key(key)
      begin
        path = Fluent::PluginHelper::RecordAccessor::Accessor.parse_parameter(key)
      rescue StandardError => e
        return [nil, "is not in the syntax of record_accessor (#{e.class}: #{e.message}). #{NESTED_KEY_SYNTAX}"]
      end
      path = [path] unless path.is_a?(Array)
      problem =
        if !path.first.is_a?(String) then "its first key is not a key of the record"
        elsif key.start_with?('$.') && path.include?('') then "it has an empty key. For a key named \"\", write $['']"
        elsif key.end_with?('.') then "it ends with a dot"
        end
      return [path, nil] unless problem
      [nil, "is read by record_accessor as #{path.inspect}, and #{problem}. #{NESTED_KEY_SYNTAX}"]
    end

    # keys is an Array type, which splits its value at each comma, so
    # keys $['a,b'] gives the keys $['a and b']. Returns how to write such a
    # key, if key and the keys after it in rest are such a key.
    def comma_hint(key, rest)
      return '' unless key.start_with?('$[') && !key.end_with?(']')
      parts = [key]
      rest.each do |k|
        break unless k.is_a?(String)
        parts << k
        break if k.end_with?(']')
      end
      return '' unless parts.size > 1 && parts.last.end_with?(']')
      joined = parts.join(',')
      " keys splits its value at each comma, so #{joined} became #{parts.map(&:inspect).join(' and ')}. " \
        "For a key with a comma, write keys as a JSON array, such as keys [#{joined.inspect}]."
    end

    # Replaces the value at path in record with the value of the block, if
    # the value exists, even if it is nil or false, as v1.0.0 does. path is an
    # Array of keys of Hashes and indexes of Arrays.
    def self.update_path(record, path)
      container = record
      last = path.size - 1
      path.each_with_index do |key, i|
        return unless child?(container, key)
        if i == last
          container[key] = yield(container[key])
        else
          container = container[key]
        end
      end
    end

    def self.child?(container, key)
      case container
      when Hash then container.has_key?(key)
      when Array then key.is_a?(Integer) && key >= -container.size && key < container.size
      else false
      end
    end
    private_class_method :child?

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
      ->(record){
        begin
          if record.has_key?(key)
            record[key] = mask_value(record[key], for_each){|v| conv.call(v, salt) }
          end
        rescue => e
          log.error "unexpected error while masking value", error_class: e.class, error: e.message
        end
        record
      }
    end

    # key_chain is an Array of keys.
    def masker_for_key_chain(conv, key_chain, opts)
      for_each = opts.mask_array_elements
      salt = opts.salt || salt_determine(key_chain.last)
      ->(record){
        begin
          self.class.update_path(record, key_chain) do |value|
            mask_value(value, for_each){|v| conv.call(v, salt) }
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
            next unless (regexp =~ self.class.stringify(value) rescue nil)
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

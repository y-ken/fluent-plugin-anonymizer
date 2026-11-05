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

    # The options of a mask for the parameters of v1.0.0, as a <mask> section
    # gives them. It is a Struct, because v1.0.0 used OpenStruct, which Ruby
    # 3.3 and later do not load.
    MaskOptions = Struct.new(:salt, :mask_array_elements, :ipv4_mask_bits, :ipv6_mask_bits)

    NESTED_KEY_NOTE = "Write a nested key such as a.b as $.a.b in keys."

    # The salts are secret, so that Fluentd does not write them in the
    # configuration that it logs.
    config_param :salt, :string, default: nil, secret: true
    config_param :salts, :array, default: nil, secret: true
    config_section :mask, param_name: :mask_config_list, required: false, multi: true do
      config_argument :method, :enum, list: MASK_METHODS.keys
      config_param :salt, :string, default: nil, secret: true

      config_param :key,             :string, default: nil,
                   deprecated: "Use keys in <mask> instead."
      config_param :keys,            :array,  default: []
      config_param :key_chain,       :string, default: nil, # for.nested.key
                   deprecated: "Use keys in <mask> instead. #{NESTED_KEY_NOTE}"
      config_param :key_chains,      :array,  default: [],  # ["for.nested.key","can.be.specified","twice.or.more"]
                   deprecated: "Use keys in <mask> instead. #{NESTED_KEY_NOTE}"
      config_param :key_pattern,     :string, default: nil
      config_param :value_pattern,   :string, default: nil
      config_param :value_in_subnet, :string, default: nil # 192.168.0.0/24

      config_param :mask_array_elements, :bool, default: false
      config_param :ipv4_mask_bits, :integer, default: nil
      config_param :ipv6_mask_bits, :integer, default: nil
    end

    # The parameters of v1.0.0. They work as in v1.0.0, after all <mask>
    # sections.
    LEGACY_HASH_METHODS = [:md5, :sha1, :sha256, :sha384, :sha512]
    LEGACY_HASH_METHODS.each do |m|
      config_param :"#{m}_keys", :string, default: nil,
                   deprecated: "Use <mask #{m}> with keys, salt and mask_array_elements true instead. #{NESTED_KEY_NOTE}"
    end
    config_param :hash_salt,   :string, default: nil, secret: true,
                 deprecated: "Use salt in <mask> instead."
    config_param :ipaddr_mask_keys, :string, default: nil,
                 deprecated: "Use <mask network> with keys, ipv4_mask_bits, ipv6_mask_bits and mask_array_elements true instead. #{NESTED_KEY_NOTE}"
    config_param :ipv4_mask_subnet, :integer, default: 24,
                 deprecated: "Use ipv4_mask_bits in <mask network> instead."
    config_param :ipv6_mask_subnet, :integer, default: 104,
                 deprecated: "Use ipv6_mask_bits in <mask network> instead."

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
        # key of v1.0.0 is a top-level key, even if it starts with $.
        if c.key
          @masks << masker_for_key(conv, c.key, c)
          if c.key.start_with?('$.', '$[')
            log.warn "key #{c.key} is the top-level key #{c.key.inspect}. Write it as keys $['#{c.key}'] in <mask>, " \
                     "because keys reads #{c.key} as a nested key."
          end
        end
        # null in keys is skipped, as in v1.0.0.
        keys = c.keys.compact
        paths = keys.each_with_index.map { |key, i| key_path(key, keys[(i + 1)..-1], c) }
        warn_same_paths(keys, paths, c)
        paths.each do |path|
          @masks << masker_for_key_chain(conv, path, c)
        end
        [c.key_chain, *c.key_chains].compact.each do |key_chain|
          @masks << masker_for_key_chain(conv, key_chain.split('.'), c)
        end
        @masks << masker_for_key_pattern(conv, c.key_pattern, c) if c.key_pattern
        @masks << masker_for_value_pattern(conv, c.value_pattern, c) if c.value_pattern
        @masks << masker_for_value_in_subnet(conv, c.value_in_subnet, c) if c.value_in_subnet
      end

      # The parameters of v1.0.0, with the salt and the order of v1.0.0.
      LEGACY_HASH_METHODS.each do |m|
        keys = public_send(:"#{m}_keys")
        next unless keys
        opts = MaskOptions.new(@hash_salt || '', true, nil, nil)
        add_legacy_masks(MASK_METHODS[m].call(opts), keys, opts)
      end
      if @ipaddr_mask_keys
        opts = MaskOptions.new(@hash_salt || '', true, @ipv4_mask_subnet, @ipv6_mask_subnet)
        add_legacy_masks(MASK_METHODS[:network].call(opts), @ipaddr_mask_keys, opts)
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

    # Warns for keys in a <mask> that are the same key, because the value of
    # the key is masked once for each of them, as in v1.0.0 and master.
    def warn_same_paths(keys, paths, opts)
      keys.zip(paths).group_by(&:last).each_value do |same|
        next if same.size < 2
        log.warn "#{same.map { |k, _| k.inspect }.join(' and ')} in keys of <mask #{opts.method}> are the same key, " \
                 "so its value is masked #{same.size} times. Write the key once."
      end
    end

    # A key of v1.0.0 with a dot is a nested key.
    def add_legacy_masks(conv, keys, opts)
      keys.split(',').map(&:strip).each do |key|
        if key.include?('.')
          @masks << masker_for_key_chain(conv, key.split('.'), opts)
        else
          @masks << masker_for_key(conv, key, opts)
        end
      end
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
      when Hash then container.key?(key)
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
          if record.key?(key)
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
            next unless AnonymizerFilter.subnet_include?(network, value)
            record[key] = conv.call(value, opts.salt || salt_determine(key))
          end
        rescue => e
          log.error "unexpected error while masking value", error_class: e.class, error: e.message
        end
        record
      }
    end

    # Whether value is in network, as ipaddr 1.2.2 (Ruby 2.7) matched it for
    # v1.0.0: an IPv4 address and its IPv4-mapped IPv6 address are in each
    # other's network. ipaddr 1.2.3 (Ruby 3.1) and later do not match them.
    def self.subnet_include?(network, value)
      return true if (network.include?(value) rescue nil)
      return false unless value.is_a?(String) && (network.ipv4? || network.ipv4_mapped?)
      address = begin
        IPAddr.new(value)
      rescue StandardError
        return false
      end
      if network.ipv4? && address.ipv4_mapped?
        network.include?(address.native)
      elsif network.ipv4_mapped? && address.ipv4?
        network.include?(address.ipv4_mapped)
      else
        false
      end
    end
  end
end

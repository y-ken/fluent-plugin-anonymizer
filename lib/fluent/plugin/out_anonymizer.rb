require 'fluent/plugin/output'
require 'fluent/plugin/filter_anonymizer'
require 'socket'

module Fluent::Plugin
  # The output plugin of v1.0.0. It masks a record as v1.0.0 does, and emits
  # it with a new tag. It is deprecated: use the filter plugin instead.
  #
  # v1.0.0 changed the tag with fluent-mixin-rewrite-tag-name and the mixins
  # of Fluentd v0.12. This plugin changes it in the same order, without them:
  # remove_tag_prefix, remove_tag_suffix, add_tag_prefix and add_tag_suffix,
  # then tag with placeholders, and then include_tag_key.
  class AnonymizerOutput < Output
    Fluent::Plugin.register_output('anonymizer', self)

    helpers :event_emitter

    HASH_ALGORITHM = %w(md5 sha1 sha256 sha384 sha512 ipaddr_mask)

    config_param :tag, :string, default: nil,
                 desc: 'The output tag. ${tag}, __TAG__, ${tag_parts[N]}, __TAG_PARTS[N]__, ${hostname} and __HOSTNAME__ are expanded.'
    config_param :hash_salt, :string, default: '', secret: true,
                 desc: 'The salt for md5_keys, sha1_keys, sha256_keys, sha384_keys and sha512_keys.'
    config_param :ipv4_mask_subnet, :integer, default: 24,
                 desc: 'Anonymize ipv4 addresses by subnet mask.'
    config_param :ipv6_mask_subnet, :integer, default: 104,
                 desc: 'Anonymize ipv6 addresses by subnet mask.'
    HASH_ALGORITHM.each do |name|
      config_param :"#{name}_keys", :string, default: nil,
                   desc: "The keys to mask with #{name}, separated by commas. a.b is a nested key."
    end
    config_param :remove_tag_prefix, :string, default: nil
    config_param :remove_tag_suffix, :string, default: nil
    config_param :add_tag_prefix, :string, default: nil
    config_param :add_tag_suffix, :string, default: nil
    config_param :include_tag_key, :bool, default: false
    config_param :tag_key, :string, default: 'tag'

    TAG_PLACEHOLDER = /(\${(tag|hostname)}|__(TAG|HOSTNAME)__)/
    TAG_PARTS_PLACEHOLDER = /__TAG_PARTS\[-?[0-9]+(?:\.\.\.?-?[0-9]+)?\]__|\$\{tag_parts\[-?[0-9]+(?:\.\.\.?-?[0-9]+)?\]\}/
    TAG_PARTS_POSITION = /\[(?<first>-?[0-9]+)(?<range_part>(?<range_type>\.\.\.?)(?<last>-?[0-9]+))?\]/

    def configure(conf)
      super
      log.warn "out_anonymizer is deprecated, and will be removed in a future release. " \
               "Use <filter> with @type anonymizer instead."

      # As v1.0.0: each parameter in the order of the configuration, with the
      # spaces removed from the keys. A key has only the last method for it.
      methods = {}
      conf.keys.select { |k| k =~ /_keys$/ }.each do |param|
        name = param.sub('_keys', '')
        raise Fluent::ConfigError, "anonymizer: unsupported key #{name}" unless HASH_ALGORITHM.include?(name)
        conf[param].gsub(' ', '').split(',').each do |key|
          methods.store(key.split('.'), name)
        end
      end
      raise Fluent::ConfigError, "anonymizer: missing hash keys setting." if methods.empty?
      unless @tag || @remove_tag_prefix || @remove_tag_suffix || @add_tag_prefix || @add_tag_suffix
        raise Fluent::ConfigError, "anonymizer: missing remove_tag_prefix, remove_tag_suffix, add_tag_prefix or add_tag_suffix."
      end

      hash_options = AnonymizerFilter::MaskOptions.new(@hash_salt, true, nil, nil)
      network_options = AnonymizerFilter::MaskOptions.new(@hash_salt, true, @ipv4_mask_subnet, @ipv6_mask_subnet)
      @masks = methods.map do |path, name|
        conv = if name == 'ipaddr_mask'
                 AnonymizerFilter::MASK_METHODS[:network].call(network_options)
               else
                 AnonymizerFilter::MASK_METHODS[name.to_sym].call(hash_options)
               end
        [path, conv]
      end

      @remove_tag_prefix_regexp = Regexp.new('^' + Regexp.escape(@remove_tag_prefix)) if @remove_tag_prefix
      @remove_tag_suffix_regexp = Regexp.new(Regexp.escape(@remove_tag_suffix) + '$') if @remove_tag_suffix
      @hostname = Socket.gethostname
      @new_tags = {}
      @new_tags_mutex = Mutex.new
    end

    def multi_workers_ready?
      true
    end

    # The number of input tags whose new tag is kept. The new tags are
    # forgotten when there are more, so a tag with a random part does not
    # use up the memory.
    NEW_TAGS_LIMIT = 1024

    def process(tag, es)
      new_tag = new_tag_for(tag)
      new_es = Fluent::MultiEventStream.new
      es.each do |time, record|
        @masks.each do |path, conv|
          begin
            AnonymizerFilter.update_path(record, path) do |value|
              value.is_a?(Array) ? value.map { |v| conv.call(v, @hash_salt) } : conv.call(value, @hash_salt)
            end
          rescue => e
            log.error "anonymizer: failed to anonymize record", error_class: e.class, error: e.message
          end
        end
        record[@tag_key] = new_tag if @include_tag_key
        new_es.add(time, record)
      end
      router.emit_stream(new_tag, new_es) unless new_es.empty?
    end

    def rewrite_tag(tag)
      tag = tag.dup
      tag.sub!(@remove_tag_prefix_regexp, '') if @remove_tag_prefix_regexp
      tag.sub!(@remove_tag_suffix_regexp, '') if @remove_tag_suffix_regexp
      tag.insert(0, @add_tag_prefix) if @add_tag_prefix
      tag << @add_tag_suffix if @add_tag_suffix
      @tag ? expand_placeholders(@tag, tag) : tag
    end

    private

    # The new tag for an input tag, kept for each input tag, so that a
    # warning about the tag is logged once for each input tag.
    def new_tag_for(tag)
      @new_tags_mutex.synchronize do
        @new_tags.fetch(tag) do
          @new_tags.clear if @new_tags.size >= NEW_TAGS_LIMIT
          @new_tags[tag] = rewrite_tag(tag).freeze
        end
      end
    end

    def expand_placeholders(str, tag)
      str = str.gsub(TAG_PLACEHOLDER) do |placeholder|
        placeholder.downcase.include?('tag') ? tag : @hostname
      end
      str.gsub(TAG_PARTS_PLACEHOLDER) do |placeholder|
        position = TAG_PARTS_POSITION.match(placeholder)
        parts = tag.split('.')
        part = if position[:range_part]
                 parts[Range.new(position[:first].to_i, position[:last].to_i, position[:range_type] == '...')]
               else
                 parts[position[:first].to_i]
               end
        if part
          part.is_a?(Array) ? part.join('.') : part
        else
          log.warn "anonymizer: #{placeholder} in tag is not in the tag '#{tag}', so it is expanded to an empty string"
          ''
        end
      end
    end
  end
end

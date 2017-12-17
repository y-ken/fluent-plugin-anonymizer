require 'fluent/mixin/rewrite_tag_name'

class Fluent::AnonymizerOutput < Fluent::Output
  Fluent::Plugin.register_output('anonymizer', self)

  # To support log_level option since Fluentd v0.10.43
  unless method_defined?(:log)
    define_method(:log) { $log }
  end

  # Define `router` method of v0.12 to support v0.10 or earlier
  unless method_defined?(:router)
    define_method("router") { Fluent::Engine }
  end

  config_param :tag, :string, :default => nil,
               :desc => 'The output tag.'
  config_param :hash_salt, :string, :default => '',
               :desc => <<-DESC
This salt affects for md5_keys sha1_keys sha256_keys sha384_keys sha512_keys settings.
It is recommend to set a hash salt to prevent rainbow table attacks.
DESC
  config_param :ipv4_mask_subnet, :integer, :default => 24,
               :desc => 'Anonymize ipv4 addresses by subnet mask.'
  config_param :ipv6_mask_subnet, :integer, :default => 104,
               :desc => 'Anonymize ipv6 addresses by subnet mask.'

  include Fluent::HandleTagNameMixin
  include Fluent::Mixin::RewriteTagName
  include Fluent::SetTagKeyMixin
  config_set_default :include_tag_key, false

  def initialize
    require 'fluent/plugin/anonymizer'
    super
  end

  def configure(conf)
    log.warn "out_anonymizer is now deprecated. It will be removed in a future release. Please consider to use filter_anonymizer."
    super
    @anonymizer = Fluent::Anonymizer.new(self, conf)
  end

  def emit(tag, es, chain)
    es.each do |time, record|
      record = @anonymizer.anonymize(record)
      emit_tag = tag.dup
      filter_record(emit_tag, time, record)
      router.emit(emit_tag, time, record)
    end
    chain.next
  end
end

module Fluent
  class AnonymizerFilter < Filter
    Plugin.register_filter('anonymizer', self)

    config_param :hash_salt, :string, :default => '',
                 :desc => <<-DESC
This salt affects for md5_keys sha1_keys sha256_keys sha384_keys sha512_keys settings.
It is recommend to set a hash salt to prevent rainbow table attacks.
DESC
    config_param :ipv4_mask_subnet, :integer, :default => 24,
                 :desc => 'Anonymize ipv4 addresses by subnet mask.'
    config_param :ipv6_mask_subnet, :integer, :default => 104,
                 :desc => 'Anonymize ipv6 addresses by subnet mask.'

    config_set_default :include_tag_key, false

    def initialize
      super
      require 'fluent/plugin/anonymizer'
    end

    def configure(conf)
      super
      @anonymizer = Anonymizer.new(self, conf)
    end

    def filter(tag, time, record)
      record = @anonymizer.anonymize(record)
    end
  end
end

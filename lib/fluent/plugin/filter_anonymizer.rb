module Fluent
  class AnonymizerFilter < Filter
    Plugin.register_filter('anonymizer', self)

    config_param :tag, :string, :default => nil
    config_param :hash_salt, :string, :default => ''
    config_param :ipv4_mask_subnet, :integer, :default => 24
    config_param :ipv6_mask_subnet, :integer, :default => 104

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

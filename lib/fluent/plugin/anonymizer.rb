require 'openssl'
require 'ipaddr'

module Fluent
  class Anonymizer

    attr_reader :log

    HASH_ALGORITHM = %w(md5 sha1 sha256 sha384 sha512 ipaddr_mask)
    DIGEST = {
      "md5" => Proc.new { OpenSSL::Digest.new('md5') },
      "sha1" => Proc.new { OpenSSL::Digest.new('sha1') },
      "sha256" => Proc.new { OpenSSL::Digest.new('sha256') },
      "sha384" => Proc.new { OpenSSL::Digest.new('sha384') },
      "sha512" => Proc.new { OpenSSL::Digest.new('sha512') }
    }

    def initialize(plugin, conf)
      @log = plugin.log
      @hash_salt = plugin.hash_salt
      @ipv4_mask_subnet = plugin.ipv4_mask_subnet
      @ipv6_mask_subnet = plugin.ipv6_mask_subnet

      @hash_keys = {}
      conf.keys.select{|k| k =~ /_keys$/}.each do |key|
        hash_algorithm_name = key.sub('_keys','')
        raise Fluent::ConfigError, "anonymizer: unsupported key #{hash_algorithm_name}" unless HASH_ALGORITHM.include?(hash_algorithm_name)
        conf[key].gsub(' ', '').split(',').each do |record_key|
          @hash_keys.store(record_key.split('.'), hash_algorithm_name)
        end
      end

      if @hash_keys.empty?
        raise Fluent::ConfigError, "anonymizer: missing hash keys setting."
      end
      log.info "anonymizer: adding anonymize rules for each field. #{@hash_keys}"

      if plugin.is_a?(Fluent::Output)
        unless have_tag_option?(plugin)
          raise Fluent::ConfigError, "anonymizer: missing remove_tag_prefix, remove_tag_suffix, add_tag_prefix or add_tag_suffix."
        end
      end
    end

    def anonymize(record)
      @hash_keys.each do |hash_key, hash_algorithm|
        record = anonymize_record(record, hash_key, hash_algorithm)
      end
      record
    end

    private

    def anonymize_record(record, key, hash_algorithm)
      if record.has_key?(key.first)
        if key.size == 1
          record[key.first] = anonymize_values(record[key.first], hash_algorithm)
        else
          record[key.first] = anonymize_record(record[key.first], key[1..-1], hash_algorithm)
        end
      end
      record
    end

    def anonymize_values(data, hash_algorithm)
      begin
        if data.is_a?(Array)
          data = data.collect { |v| anonymize_value(v, hash_algorithm, @hash_salt) }
        else
          data = anonymize_value(data, hash_algorithm, @hash_salt)
        end
      rescue => e
        log.error "anonymizer: failed to anonymize record. :message=>#{e.message} :data=>#{data}"
        log.error e.backtrace.join("\n")
      end
      data
    end

    def anonymize_value(message, algorithm, salt)
      case algorithm
      when 'md5','sha1','sha256','sha384','sha512'
        DIGEST[algorithm].call.update(salt).update(message.to_s).hexdigest
      when 'ipaddr_mask'
        address = IPAddr.new(message)
        subnet = address.ipv4? ? @ipv4_mask_subnet : @ipv6_mask_subnet
        address.mask(subnet).to_s
      else
        log.warn "anonymizer: unknown algorithm #{algorithm} has called."
      end
    end

    def have_tag_option?(plugin)
      plugin.tag ||
        plugin.remove_tag_prefix || plugin.remove_tag_suffix ||
        plugin.add_tag_prefix || plugin.add_tag_suffix
    end
  end
end

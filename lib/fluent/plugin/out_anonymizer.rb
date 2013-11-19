class Fluent::AnonymizerOutput < Fluent::Output
  Fluent::Plugin.register_output('anonymizer', self)
  
  HASH_ALGORITHM = %w(md5 sha1 sha256 sha384 sha512 ipv4_mask)
  config_param :hash_salt, :string, :default => ''
  config_param :ipv4_mask_subnet, :integer, :default => 24

  include Fluent::HandleTagNameMixin

  include Fluent::SetTagKeyMixin
  config_set_default :include_tag_key, false

  DIGEST = {
    "md5" => Proc.new { Digest::MD5 },
    "sha1" => Proc.new { Digest::SHA1 },
    "sha256" => Proc.new { Digest::SHA256 },
    "sha384" => Proc.new { Digest::SHA384 },
    "sha512" => Proc.new { Digest::SHA512 }
  }

  def initialize
    require 'digest/sha2'
    require 'ipaddr'
    super
  end
  
  def configure(conf)
    super

    @hash_keys = Hash.new
    conf.keys.select{|k| k =~ /_keys$/}.each do |key|
      hash_algorithm_name = key.sub('_keys','')
      raise Fluent::ConfigError, "anonymizer: unsupported key #{hash_algorithm_name}" unless HASH_ALGORITHM.include?(hash_algorithm_name)
      conf[key].gsub(' ', '').split(',').each do |record_key|
        @hash_keys.store(record_key, hash_algorithm_name)
      end
    end

    if @hash_keys.count < 1
      raise Fluent::ConfigError, "anonymizer: missing hash keys setting."
    end

    if ( !@remove_tag_prefix && !@remove_tag_suffix && !@add_tag_prefix && !@add_tag_suffix )
      raise Fluent::ConfigError, "anonymizer: missing remove_tag_prefix, remove_tag_suffix, add_tag_prefix or add_tag_suffix."
    end
  end

  def emit(tag, es, chain)
    es.each do |time, record|
      record = filter_anonymize_record(record)
      filter_record(tag, time, record)
      Fluent::Engine.emit(tag, time, record)
    end
    chain.next
  end

  def filter_anonymize_record(record)
    @hash_keys.each do |hash_key, hash_algorithm|
      next unless record.include?(hash_key)
      if record[hash_key].is_a?(Array)
        record[hash_key] = record[hash_key].collect { |v| anonymize(v, hash_algorithm, @hash_salt) }
      else
        record[hash_key] = anonymize(record[hash_key], hash_algorithm, @hash_salt)
      end
    end
    return record
  end

  def anonymize(message, algorithm, salt)
    case algorithm
    when 'md5','sha1','sha256','sha384','sha512'
      DIGEST[algorithm].call.hexdigest(salt + message.to_s)
    when 'ipv4_mask'
      IPAddr.new(message).mask(@ipv4_mask_subnet).to_s
    else
      $log.warn "anonymizer: unknown algorithm #{algorithm} has called."
    end
  end
end

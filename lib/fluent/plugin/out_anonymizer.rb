class Fluent::AnonymizerOutput < Fluent::Output
  Fluent::Plugin.register_output('anonymizer', self)
  
  HASH_ALGORITHM = %w(md5 sha1 sha256 sha384 sha512 ipaddr_mask)
  config_param :hash_salt, :string, :default => ''
  config_param :ipv4_mask_subnet, :integer, :default => 24
  config_param :ipv6_mask_subnet, :integer, :default => 104

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
    $log.info "anonymizer: adding anonymize rules for each field. #{@hash_keys}"

    if ( !@remove_tag_prefix && !@remove_tag_suffix && !@add_tag_prefix && !@add_tag_suffix )
      raise Fluent::ConfigError, "anonymizer: missing remove_tag_prefix, remove_tag_suffix, add_tag_prefix or add_tag_suffix."
    end
  end

  def emit(tag, es, chain)
    es.each do |time, record|
      @hash_keys.each do |hash_key, hash_algorithm|
        next unless record.include?(hash_key)
        record[hash_key] = filter_anonymize_record(record[hash_key], hash_algorithm)
      end
      t = tag.dup
      filter_record(t, time, record)
      Fluent::Engine.emit(t, time, record)
    end
    chain.next
  end

  def filter_anonymize_record(data, hash_algorithm)
    begin
      if data.is_a?(Array)
        data = data.collect { |v| anonymize(v, hash_algorithm, @hash_salt) }
      else
        data = anonymize(data, hash_algorithm, @hash_salt)
      end
    rescue StandardError => e
      $log.error "anonymizer: failed to anonymize record. :message=>#{e.message} :data=>#{data}"
      $log.error e.backtrace.join("\n")
    end
    data
  end

  def anonymize(message, algorithm, salt)
    case algorithm
    when 'md5','sha1','sha256','sha384','sha512'
      DIGEST[algorithm].call.hexdigest(salt + message.to_s)
    when 'ipaddr_mask'
      address = IPAddr.new(message)
      subnet = address.ipv4? ? @ipv4_mask_subnet : @ipv6_mask_subnet
      address.mask(subnet).to_s
    else
      $log.warn "anonymizer: unknown algorithm #{algorithm} has called."
    end
  end
end

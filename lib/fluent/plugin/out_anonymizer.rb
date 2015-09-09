require 'fluent/mixin/rewrite_tag_name'

class Fluent::AnonymizerOutput < Fluent::Output
  Fluent::Plugin.register_output('anonymizer', self)

  # To support log_level option since Fluentd v0.10.43
  unless method_defined?(:log)
    define_method(:log) { $log }
  end

  HASH_ALGORITHM = %w(md5 sha1 sha256 sha384 sha512 ipaddr_mask)
  config_param :tag, :string, :default => nil
  config_param :hash_salt, :string, :default => nil
  config_param :hash_salt_path, :string, :default => nil
  config_param :ipv4_mask_subnet, :integer, :default => 24
  config_param :ipv6_mask_subnet, :integer, :default => 104

  include Fluent::HandleTagNameMixin
  include Fluent::Mixin::RewriteTagName
  include Fluent::SetTagKeyMixin
  config_set_default :include_tag_key, false

  DIGEST = {
    "md5" => Proc.new { OpenSSL::Digest.new('md5') },
    "sha1" => Proc.new { OpenSSL::Digest.new('sha1') },
    "sha256" => Proc.new { OpenSSL::Digest.new('sha256') },
    "sha384" => Proc.new { OpenSSL::Digest.new('sha384') },
    "sha512" => Proc.new { OpenSSL::Digest.new('sha512') }
  }

  def initialize
    require 'openssl'
    require 'ipaddr'
    super
  end

  def configure(conf)
    super

    configure_hash_salt

    @hash_keys = Hash.new
    conf.keys.select{|k| k =~ /_keys$/}.each do |key|
      hash_algorithm_name = key.sub('_keys','')
      raise Fluent::ConfigError, "anonymizer: unsupported key #{hash_algorithm_name}" unless HASH_ALGORITHM.include?(hash_algorithm_name)
      conf[key].gsub(' ', '').split(',').each do |record_key|
        @hash_keys.store(record_key.split('.'), hash_algorithm_name)
      end
    end

    if @hash_keys.count < 1
      raise Fluent::ConfigError, "anonymizer: missing hash keys setting."
    end
    log.info "anonymizer: adding anonymize rules for each field. #{@hash_keys}"

    if ( !@tag && !@remove_tag_prefix && !@remove_tag_suffix && !@add_tag_prefix && !@add_tag_suffix )
      raise Fluent::ConfigError, "anonymizer: missing remove_tag_prefix, remove_tag_suffix, add_tag_prefix or add_tag_suffix."
    end
  end

  def emit(tag, es, chain)
    es.each do |time, record|
      @hash_keys.each do |hash_key, hash_algorithm|
        record = filter_anonymize_record(record, hash_key, hash_algorithm)
      end
      emit_tag = tag.dup
      filter_record(emit_tag, time, record)
      Fluent::Engine.emit(emit_tag, time, record)
    end
    chain.next
  end

  def filter_anonymize_record(record, key, hash_algorithm)
    if record.has_key?(key.first)
      if key.size == 1
        record[key.first] = filter_anonymize_value(record[key.first], hash_algorithm)
      else
        record[key.first] = filter_anonymize_record(record[key.first], key[1..-1], hash_algorithm)
      end
    end
    return record
  end

  def filter_anonymize_value(data, hash_algorithm)
    begin
      if data.is_a?(Array)
        data = data.collect { |v| anonymize(v, hash_algorithm, @hash_salt) }
      else
        data = anonymize(data, hash_algorithm, @hash_salt)
      end
    rescue StandardError => e
      log.error "anonymizer: failed to anonymize record. :message=>#{e.message} :data=>#{data}"
      log.error e.backtrace.join("\n")
    end
    data
  end

  def anonymize(message, algorithm, salt)
    case algorithm
    when 'md5','sha1','sha256','sha384','sha512'
      OpenSSL::HMAC.hexdigest(DIGEST[algorithm].call, salt, message.to_s)
    when 'ipaddr_mask'
      address = IPAddr.new(message)
      subnet = address.ipv4? ? @ipv4_mask_subnet : @ipv6_mask_subnet
      address.mask(subnet).to_s
    else
      log.warn "anonymizer: unknown algorithm #{algorithm} has called."
    end
  end

  private
  def configure_hash_salt
    @hash_salt ||= read_hash_salt || ""
  end

  def read_hash_salt
    return nil unless @hash_salt_path

    ensure_hash_salt_file
    File.open(@hash_salt_path, 'rb') do |file|
      file.read
    end
  end

  def ensure_hash_salt_file
    return if File.exist?(@hash_salt_path)

    ensure_directory(File.dirname(@hash_salt_path))

    require 'securerandom'
    salt = SecureRandom.hex
    File.open(@hash_salt_path, 'wb', 0600) do |file|
      file.print(salt)
    end
  end

  def ensure_directory(path)
    return if File.directory?(path)

    require 'fileutils'
    if defined?(Fluent::DEFAULT_DIR_PERMISSION)
      permission = Fluent::DEFAULT_DIR_PERMISSION
    else
      permission = 0644
    end
    FileUtils.mkdir_p(path, :mode => permission)
  end
end


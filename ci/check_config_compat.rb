# Checks that the configurations in test/compat/configs still work with the
# code in this repository as they do with a released version of the gem.
#
# Fluentd runs with each configuration. The configuration reads the records
# of test/compat/records.rb (test/compat/plugin/in_compat_records.rb) and
# writes each output record (test/compat/plugin/out_compat_dump.rb). The check
# compares the output of this repository with the output of the released gem,
# record by record and value by value:
#
# * A value that the released gem outputs as it is in the input (raw) may be
#   masked or null with this repository: that fixes a leak.
# * Any other value must be the same: a value that the released gem masked
#   must not become raw, null or another digest.
# * Each record that the released gem outputs must be output once, with the
#   same tag.
# * A record that the released gem does not output may be output. A value in
#   it must not be raw at a key where the released gem masked the value with
#   a hash method in another record, because a hash method masks any value.
#   An address in it must not be raw at a key where the released gem masked
#   an address (a network mask leaves a value that is not an address).
# * A String in the records (5 bytes or more) must not be in the log, as it
#   is or escaped as inspect writes it, unless the released gem logs it too.
#   Fluentd is stopped after it emits the records, so the log at shutdown is
#   checked too.
#
# A raw value is a value that still shows the input value: the input value,
# the same bytes in another encoding, to_s or inspect of the input value, the
# input value after scrub, the same address written as IPAddr#to_s writes it,
# or a value that contains a String of the input value of 5 bytes or more.
#
# The output of the released gem comes from a run of the released gem, or
# from a baseline: a file that keeps the output of a run. The baseline of
# 1.0.0 is made on Ruby 2.7, so that the check compares with v1.0.0 on Ruby
# 2.7 on any Ruby. v1.0.0 outputs some values differently on later Ruby
# versions, such as an IPv4-mapped address in value_in_subnet (ipaddr 1.2.3).
#
# Usage:
#   ruby ci/check_config_compat.rb [--fail-on-skip] [RELEASED_VERSION]
#     Runs RELEASED_VERSION (default: the latest version on rubygems.org).
#   ruby ci/check_config_compat.rb [--fail-on-skip] --baseline FILE
#     Compares with the output in FILE, without the released gem.
#   ruby ci/check_config_compat.rb [--fail-on-skip] --baseline FILE RELEASED_VERSION
#     Runs RELEASED_VERSION, fails if FILE is not its output, and compares.
#   ruby ci/check_config_compat.rb --write-baseline FILE RELEASED_VERSION
#     Writes the output of RELEASED_VERSION to FILE.
#
# On Ruby 3.4 and later, a run of v1.0.0 can report a Hash value, or an
# Array that holds a Hash, as broken ("masked -> another value"), and
# --baseline FILE 1.0.0 also says that FILE is not the output of 1.0.0.
# v1.0.0 hashes such a value in the format of Hash#inspect of the running
# Ruby, which changed in Ruby 3.4, while this repository hashes it in the
# format of Ruby 3.3 (#37). Use --baseline FILE without a version there, to
# compare with the output of v1.0.0 on Ruby 2.7.
#
# A broken configuration fails the check, unless the major version in the
# gemspec is greater than the major version of the released gem. Then it is
# only reported, because a new major version may break configurations.
#
# A configuration that the released gem fails to run is skipped. With
# --fail-on-skip, a skipped configuration fails the check too, so that a
# broken environment of the released gem is not taken as a pass.
#
# FLUENTD_VERSION sets the requirement of the fluentd gem (default: ">= 0.14.0").
# The released gem runs on the same version of fluentd as this repository.
# COMPAT_BUNDLE_PATH sets the directory of the gems (default: tmp/compat-bundle).
# COMPAT_ONLY runs only the configurations whose path matches it. The check
# fails if it matches none.
# COMPAT_VERBOSE=1 shows each allowed change.

require "digest"
require "ipaddr"
require "json"
require "net/http"
require "open3"
require "rubygems"
require "timeout"
require "tmpdir"

ROOT = File.expand_path("..", __dir__)
CONFIGS = Dir[File.join(ROOT, "test/compat/configs/*.conf")].sort.grep(Regexp.new(ENV.fetch("COMPAT_ONLY", "")))
PLUGIN_DIR = File.join(ROOT, "test/compat/plugin")
RECORDS_FILE = File.join(ROOT, "test/compat/records.rb")
FLUENTD_REQUIREMENT = ENV.fetch("FLUENTD_VERSION", "").empty? ? ">= 0.14.0" : ENV["FLUENTD_VERSION"]
BUNDLE_PATH = File.expand_path(ENV.fetch("COMPAT_BUNDLE_PATH", File.join(ROOT, "tmp/compat-bundle")))
TIMEOUT = 60
VERBOSE = ENV["COMPAT_VERBOSE"] == "1"
# A String in the records that is shorter is not looked for in the log.
LOGGED_MIN_BYTES = 5
# A String in the input that is shorter is not looked for in an output value:
# "42" may be in a digest.
RAW_MIN_BYTES = 5
# A digest of a hash method. A String of the input that has only hex digits,
# such as "12345", may be in a digest by chance, so it is not looked for in a
# digest.
DIGEST = /\A\h{32,}\z/

def latest_released_version
  uri = URI("https://rubygems.org/api/v1/versions/fluent-plugin-anonymizer/latest.json")
  JSON.parse(Net::HTTP.get(uri)).fetch("version")
end

def current_version
  Gem::Specification.load(File.join(ROOT, "fluent-plugin-anonymizer.gemspec")).version.to_s
end

# Runs a command without the Bundler environment of this process, if any, so
# that `bundle exec ruby ci/check_config_compat.rb` works too.
def unbundled(&block)
  defined?(Bundler) ? Bundler.with_unbundled_env(&block) : yield
end

def write_gemfile(dir, fluentd_requirement, plugin_line)
  File.write(File.join(dir, "Gemfile"), <<~GEMFILE)
    source "https://rubygems.org"
    gem "fluentd", #{fluentd_requirement.inspect}
    #{plugin_line}
  GEMFILE
  env = { "BUNDLE_GEMFILE" => File.join(dir, "Gemfile"), "BUNDLE_PATH" => BUNDLE_PATH }
  out, status = unbundled { Open3.capture2e(env, "bundle", "install", "--quiet", chdir: dir) }
  abort "bundle install failed in #{dir}:\n#{out}" unless status.success?
  env
end

def fluentd_version(env, dir)
  # Only the standard output, because the gemspec may warn on the standard error.
  out, err, status = unbundled { Open3.capture3(env, "bundle", "exec", "ruby", "-e", 'require "fluent/version"; print Fluent::VERSION', chdir: dir) }
  status.success? ? out : abort("cannot read the version of fluentd in #{dir}:\n#{out}#{err}")
end

def load_records
  TOPLEVEL_BINDING.eval(File.read(RECORDS_FILE, encoding: "UTF-8"), RECORDS_FILE)
end

# The Strings in value, as they are.
def strings_in(value, found = [])
  case value
  when String then found << value
  when Hash then value.each_value { |v| strings_in(v, found) }
  when Array then value.each { |v| strings_in(v, found) }
  end
  found
end

# The bytes of a String as they may be in the log: as they are, scrubbed,
# and escaped as inspect writes them, because Fluentd writes the fields of a
# log line with inspect. "田中太郎".b is written as \xE7\x94\xB0..., and a
# String that is not valid UTF-8 is escaped too.
def log_forms(s)
  [s, s.scrub, s.inspect[1..-2]].map(&:b).uniq
end

# The Strings of the records that are in the log.
def logged_strings(records, log)
  strings_in(records).select { |s| s.bytesize >= LOGGED_MIN_BYTES && log_forms(s).any? { |f| log.include?(f) } }.uniq
end

def stop(thread)
  Process.kill(:TERM, thread.pid)
rescue Errno::ESRCH
  nil
end

# Runs Fluentd with config. When Fluentd has emitted all the records, it is
# stopped, and its output is read to the end, so that a log line written at
# shutdown is checked too. Returns a Hash:
#   status: :ok when Fluentd emits all the records and stops, or :error when
#           it exits before it emits them, or does not stop in TIMEOUT seconds
#   outputs: {index => [tag, record]}
#   duplicates: the indexes of the records output more than once
#   message: why the run failed, for :error
#   errors: the messages of the [error] lines
#   logged: the Strings of the records that are in the log
def run_config(env, dir, config, records, options = [])
  result = { status: :error, outputs: {}, duplicates: [], errors: [] }
  raised = [] # other lines with an exception
  emitted = false
  log = "".b # the log lines as they are, which may have bytes that are not valid UTF-8
  unbundled do
    Open3.popen2e(env, "bundle", "exec", "fluentd", "-c", config, "-p", PLUGIN_DIR, "--no-supervisor", *options, chdir: dir) do |stdin, out, thread|
      stdin.close
      begin
        Timeout.timeout(TIMEOUT) do
          out.each_line do |raw_line|
            line = raw_line.scrub # to match a log line that may have a value that is not valid UTF-8
            if line.start_with?("COMPAT-RECORD ")
              _, index, data = line.split(" ", 3)
              index = Integer(index)
              result[:duplicates] << index if result[:outputs].key?(index)
              result[:outputs][index] = Marshal.load(data.strip.unpack1("m0"))
            elsif line.start_with?("COMPAT-EMITTED ")
              emitted = true
              stop(thread)
            else
              log << raw_line.b
              if line =~ /\[error\]: (.*)/
                message = $1.strip
                # "config error in:" is followed by the configuration and then by the error.
                result[:errors] << message[0, 300] unless message.end_with?(" in:")
              elsif line =~ /(\w+(?:::\w+)*Error\b.*)/
                # An exception that is not logged, such as a NameError at start.
                raised << $1.strip[0, 300]
              end
            end
          end
        end
        if emitted
          result[:status] = :ok
        else
          result[:message] = result[:errors].first || raised.first || "Fluentd exited before it emitted the records"
        end
      rescue Timeout::Error
        result[:message] =
          if emitted
            "Fluentd did not stop in #{TIMEOUT} seconds after it emitted the records"
          else
            result[:errors].first || raised.first || "the records were not emitted in #{TIMEOUT} seconds"
          end
      ensure
        begin
          Process.kill(:TERM, thread.pid)
          unless thread.join(10)
            Process.kill(:KILL, thread.pid)
            thread.join
          end
        rescue Errno::ESRCH
          thread.join
        end
      end
    end
  end
  result[:errors].uniq!
  result[:logged] = logged_strings(records, log)
  result
end

MISSING = Object.new
def MISSING.inspect; "(missing)"; end

# Whether a and b are the same, with the encoding of each String.
def same?(a, b, bytes_only = false)
  return false unless a.class == b.class
  case a
  when String then a.b == b.b && (bytes_only || a.encoding == b.encoding)
  when Array then a.size == b.size && a.zip(b).all? { |x, y| same?(x, y, bytes_only) }
  when Hash
    a.size == b.size && a.keys.zip(b.keys).all? { |x, y| same?(x, y, bytes_only) } &&
      a.all? { |k, v| same?(v, b[k], bytes_only) }
  when Float then a.eql?(b) || (a.nan? && b.nan?)
  else a == b
  end
end

# Whether out still shows the input value (see RAW_MIN_BYTES): the same
# value, the same bytes in another encoding, to_s or inspect of the input,
# the input after scrub, the same address written by IPAddr#to_s, or a value
# with a String that contains a String of the input of RAW_MIN_BYTES or
# more, as it is or after scrub, unless that String is a digest (DIGEST). So
# a mask that returns v.to_s for a value that it cannot mask, or
# "::ffff:10.1.2.3" for "10.1.2.3", does not mask.
def raw?(input, out)
  return false if input.equal?(MISSING) || out.equal?(MISSING)
  return true if same?(input, out, true)
  outs = strings_in(out).map(&:b)
  return false if outs.empty?
  if out.is_a?(String)
    forms = [input.to_s, input.inspect]
    forms << input.scrub if input.is_a?(String)
    return true if forms.any? { |f| f.b == out.b }
  end
  parts = strings_in(input).flat_map { |s| [s.b, s.scrub.b] }.select { |s| s.bytesize >= RAW_MIN_BYTES }.uniq
  texts = outs.reject { |o| o.match?(DIGEST) }
  return true if parts.any? { |part| texts.any? { |o| o.include?(part) } }
  return false unless input.is_a?(String) && out.is_a?(String) && !input.include?("/")
  begin
    IPAddr.new(input).to_s.b == out.b
  rescue StandardError
    false
  end
end

def short(v)
  v.equal?(MISSING) ? "(missing)" : v.inspect[0, 80]
end

# Compares the values at path. Adds a problem for a change that is not
# allowed, and counts each allowed change in changes.
def compare(input, before, after, path, problems, changes)
  return if same?(before, after)
  where = path.map(&:inspect).join(" ")
  if before.is_a?(Hash) && after.is_a?(Hash)
    (before.keys | after.keys).each do |k|
      compare(input.is_a?(Hash) && input.key?(k) ? input[k] : MISSING,
              before.key?(k) ? before[k] : MISSING, after.key?(k) ? after[k] : MISSING,
              path + [k], problems, changes)
    end
    return
  end
  if before.is_a?(Array) && after.is_a?(Array)
    if before.size != after.size
      problems << "#{where}: an Array of #{before.size} became #{after.size} (#{short(before)} became #{short(after)})"
      return
    end
    before.each_index do |i|
      compare(input.is_a?(Array) && input.size == before.size ? input[i] : MISSING,
              before[i], after[i], path + [i], problems, changes)
    end
    return
  end
  allowed = nil
  kind =
    if raw?(input, before)
      if after.nil? then allowed = "raw -> null"
      elsif after.equal?(MISSING) then "raw -> removed"
      elsif raw?(input, after) then "raw -> another raw"
      else allowed = "raw -> masked"
      end
    elsif raw?(input, after) then "masked -> raw"
    elsif after.nil? then "masked -> null"
    else "masked -> another value"
    end
  if allowed
    changes[allowed] += 1
    puts "    #{where}: #{allowed} (#{short(before)} became #{short(after)})" if VERBOSE
  else
    problems << "#{where}: #{kind} (#{short(before)} became #{short(after)})"
  end
end

def address?(value)
  value.is_a?(String) && !!IPAddr.new(value)
rescue StandardError
  false
end

# Adds to found how the released gem masked the value at each path of a
# record that it output: :hash where it output a digest, and :network where
# it output another address. An index of an Array is [] in a path.
def masked_paths(input, out, found, path = [])
  if out.is_a?(Hash) && input.is_a?(Hash)
    out.each { |k, v| masked_paths(input.key?(k) ? input[k] : MISSING, v, found, path + [k]) }
  elsif out.is_a?(Array) && input.is_a?(Array) && out.size == input.size
    out.each_with_index { |v, i| masked_paths(input[i], v, found, path + [[]]) }
  elsif !input.equal?(MISSING) && out.is_a?(String) && !raw?(input, out)
    kind = if out.match?(DIGEST) then :hash
           elsif address?(out) then :network
           end
    found[path] = (found[path] || []) | [kind] if kind
  end
end

# Whether the input value at a path must not be raw in a record that the
# released gem did not output (see the top of this file). An empty Array or
# Hash shows nothing, so it may be raw.
def must_mask?(input, masked, path)
  kinds = masked[path] || []
  (kinds.include?(:hash) || (kinds.include?(:network) && address?(input))) &&
    !(input.respond_to?(:empty?) && !input.is_a?(String) && input.empty?)
end

# A value, and each value in the Hashes and Arrays in it, with its path. An
# index of an Array is [] in a path.
def nested_values(value, path = [], found = [])
  found << [path, value]
  case value
  when Hash then value.each { |k, v| nested_values(v, path + [k], found) }
  when Array then value.each { |v| nested_values(v, path + [[]], found) }
  end
  found
end

# Adds a problem for each value of a record that the released gem did not
# output that is raw where the released gem masked such a value. Where the
# output has another shape than the input, such as an Array of another size
# or a Hash replaced by a String, a value of the output cannot be matched
# with a value of the input by its path. Then no value in the output may be
# raw for a value in the input that must be masked.
def check_new_record(input, out, masked, path, where, problems)
  if must_mask?(input, masked, path) && raw?(input, out)
    problems << "#{where.map(&:inspect).join(' ')}: raw where the released gem masked the value in another record (#{short(out)})"
  elsif out.is_a?(Hash) && input.is_a?(Hash)
    out.each { |k, v| check_new_record(input[k], v, masked, path + [k], where + [k], problems) if input.key?(k) }
  elsif out.is_a?(Array) && input.is_a?(Array) && out.size == input.size
    out.each_with_index { |v, i| check_new_record(input[i], v, masked, path + [[]], where + [i], problems) }
  elsif [input, out].any? { |v| v.is_a?(Hash) || v.is_a?(Array) }
    outs = nested_values(out).map(&:last)
    raw = nested_values(input, path).flat_map do |p, value|
      must_mask?(value, masked, p) ? outs.select { |o| raw?(value, o) } : []
    end
    unless raw.empty?
      problems << "#{where.map(&:inspect).join(' ')}: raw where the released gem masked the value in another record, " \
                  "in another shape (#{short(raw.first)} in #{short(out)})"
    end
  end
end

# Returns [problems, changes] for the results of the two runs.
def compare_results(records, before, after)
  problems = []
  changes = Hash.new(0)
  after[:duplicates].uniq.each { |i| problems << "record #{i} is output more than once" }
  before[:outputs].keys.sort.each do |i|
    unless after[:outputs].key?(i)
      problems << "record #{i} is not output"
      next
    end
    btag, brecord = before[:outputs][i]
    atag, arecord = after[:outputs][i]
    problems << "record #{i}: the tag #{btag.inspect} became #{atag.inspect}" unless btag == atag
    compare(records[i], brecord, arecord, ["record #{i}"], problems, changes)
  end
  new_records = (after[:outputs].keys - before[:outputs].keys).sort
  new_records.reject { |i| i.between?(0, records.size - 1) }.each do |i|
    problems << "record #{i} is output, but there is no record #{i} in the input"
  end
  new_records.select! { |i| i.between?(0, records.size - 1) }
  unless new_records.empty?
    masked = {}
    before[:outputs].each { |i, (_, record)| masked_paths(records[i], record, masked) }
    new_records.each do |i|
      changes["record not output before -> output"] += 1
      check_new_record(records[i], after[:outputs][i][1], masked, [], ["record #{i}"], problems)
    end
  end
  (after[:logged] - before[:logged]).each { |s| problems << "a String of the records is in the log: #{short(s[0, 30])}" }
  [problems, changes]
end

# A baseline keeps the result of the released gem for each configuration, in
# JSON, so that a review can read what the released gem output, and what a
# new baseline changes. It has the version of the gem, Ruby and Fluentd, the
# digest of test/compat/records.rb, and for each configuration its digest and
# the result of run_config. Each output record is {"tag": TAG, "record":
# RECORD}, at the index of the record. JSON has no encoding of a String, and
# no key that is not a String, so the values are written as follows:
#
# * A String in UTF-8 that is valid is a JSON String.
# * Another String is {"$string": TEXT, "encoding": ENCODING} if its bytes
#   are valid UTF-8, or {"$base64": BASE64, "encoding": ENCODING} if not.
# * A Hash whose keys are all Strings of the first kind, none of which starts
#   with "$", is a JSON object. Another Hash is {"$hash": [[KEY, VALUE], ...]}.
# * A Float that is not finite is {"$float": "NaN"}, "Infinity" or "-Infinity".
BASELINE_KEYS = [:status, :outputs, :duplicates, :message, :errors, :logged]

def digest_of(path)
  Digest::SHA256.file(path).hexdigest[0, 16]
end

def plain_string?(v)
  v.is_a?(String) && v.encoding == Encoding::UTF_8 && v.valid_encoding?
end

def to_baseline_value(v)
  case v
  when String
    return v if plain_string?(v)
    text = v.dup.force_encoding(Encoding::UTF_8)
    if text.valid_encoding?
      { "$string" => text, "encoding" => v.encoding.name }
    else
      { "$base64" => [v].pack("m0"), "encoding" => v.encoding.name }
    end
  when Hash
    if v.keys.all? { |k| plain_string?(k) && !k.start_with?("$") }
      v.each_with_object({}) { |(k, x), h| h[k] = to_baseline_value(x) }
    else
      { "$hash" => v.map { |k, x| [to_baseline_value(k), to_baseline_value(x)] } }
    end
  when Array then v.map { |x| to_baseline_value(x) }
  when Float then v.finite? ? v : { "$float" => v.to_s }
  when Integer, true, false, nil then v
  else raise ArgumentError, "a baseline cannot keep #{v.class}: #{v.inspect[0, 80]}"
  end
end

def from_baseline_value(v)
  case v
  when Hash
    if v.key?("$string") then v["$string"].b.force_encoding(v["encoding"])
    elsif v.key?("$base64") then v["$base64"].unpack1("m0").force_encoding(v["encoding"])
    elsif v.key?("$hash") then v["$hash"].each_with_object({}) { |(k, x), h| h[from_baseline_value(k)] = from_baseline_value(x) }
    elsif v.key?("$float") then { "NaN" => Float::NAN, "Infinity" => Float::INFINITY, "-Infinity" => -Float::INFINITY }.fetch(v["$float"])
    else v.each_with_object({}) { |(k, x), h| h[k] = from_baseline_value(x) }
    end
  when Array then v.map { |x| from_baseline_value(x) }
  else v
  end
end

# A value in a baseline that is written on one line: a value that is not an
# Array or a Hash, a String or a Float written as a Hash, and an Array of them.
def one_line?(v)
  case v
  when Hash then (v.key?("$string") || v.key?("$base64") || v.key?("$float"))
  when Array then v.all? { |x| !x.is_a?(Array) && one_line?(x) } && v.to_json.size <= 100
  else true
  end
end

# JSON with each value of a Hash or an Array on its own line, except the
# values of one_line?, so that a diff shows each value that changed.
def baseline_json(v, indent = "")
  return v.to_json if one_line?(v)
  inner = indent + "  "
  if v.is_a?(Hash)
    return "{}" if v.empty?
    "{\n" + v.map { |k, x| "#{inner}#{k.to_json}: #{baseline_json(x, inner)}" }.join(",\n") + "\n#{indent}}"
  else
    "[\n" + v.map { |x| "#{inner}#{baseline_json(x, inner)}" }.join(",\n") + "\n#{indent}]"
  end
end

# A String of the baseline itself, such as a digest, in UTF-8.
def utf8(s)
  s.to_s.encode(Encoding::UTF_8)
end

def baseline_result(result)
  {
    "status" => utf8(result[:status]),
    "message" => result[:message],
    "errors" => result[:errors],
    "duplicates" => result[:duplicates],
    "logged" => result[:logged],
    "outputs" => result[:outputs].sort.each_with_object({}) { |(i, (tag, record)), h| h[utf8(i)] = { "tag" => tag, "record" => record } },
  }
end

def write_baseline(file, released, fluentd, results)
  data = {
    "comment" => "The output of fluent-plugin-anonymizer #{released} for each configuration in test/compat/configs. " \
                 "Written by: ruby ci/check_config_compat.rb --write-baseline #{file} #{released}",
    "version" => utf8(released),
    "ruby" => utf8(RUBY_VERSION),
    "fluentd" => utf8(fluentd),
    "records" => utf8(digest_of(RECORDS_FILE)),
    "configs" => results.each_with_object({}) do |(config, result), h|
      h[utf8(File.basename(config))] = { "digest" => utf8(digest_of(config)) }.merge(baseline_result(result))
    end,
  }
  File.write(file, baseline_json(to_baseline_value(data)) + "\n")
  # The baseline must keep each value as it is, with the encoding of each String.
  _, kept = read_baseline(file)
  results.each do |config, result|
    k = kept[File.basename(config)][1]
    next if BASELINE_KEYS.all? { |key| same?(k[key], key == :outputs ? result[key].sort.to_h : result[key]) }
    abort "#{file} does not keep the result of #{File.basename(config)} as it is"
  end
end

def read_baseline(file)
  data = from_baseline_value(JSON.parse(File.read(file, encoding: "UTF-8")))
  header = data.reject { |k, _| k == "configs" }
  results = data.fetch("configs").each_with_object({}) do |(name, r), h|
    result = {
      status: r.fetch("status").to_sym,
      outputs: r.fetch("outputs").each_with_object({}) { |(i, o), out| out[Integer(i)] = [o.fetch("tag"), o.fetch("record")] },
      duplicates: r.fetch("duplicates"),
      message: r.fetch("message"),
      errors: r.fetch("errors"),
      logged: r.fetch("logged"),
    }
    h[name] = [r.fetch("digest"), result]
  end
  [header, results]
end

# The baseline is out of date when the records or a configuration changed.
def stale_baseline(file, header, results)
  stale = []
  stale << "test/compat/records.rb" unless header["records"] == digest_of(RECORDS_FILE)
  CONFIGS.each do |config|
    name = File.basename(config)
    stale << name unless results[name] && results[name][0] == digest_of(config)
  end
  stale
end

def regenerate_note(file, version)
  "Write it again with fluent-plugin-anonymizer #{version} on Ruby 2.7: " \
    "ruby ci/check_config_compat.rb --write-baseline #{file} #{version}"
end

# The FILE after option, or nil without option.
def file_option(option)
  i = ARGV.index(option) or return nil
  file = ARGV.slice!(i, 2)[1]
  abort "#{option} needs FILE" if file.nil? || file.start_with?("-")
  file
end

fail_on_skip = !ARGV.delete("--fail-on-skip").nil?
baseline_file = file_option("--baseline")
write_file = file_option("--write-baseline")
abort "--write-baseline needs RELEASED_VERSION" if write_file && ARGV[0].nil?
abort "#{baseline_file} does not exist" if baseline_file && !File.exist?(baseline_file)
if CONFIGS.empty?
  abort "COMPAT_ONLY=#{ENV.fetch('COMPAT_ONLY', '')} selects no configuration in test/compat/configs"
end
if baseline_file
  baseline_header, baseline = read_baseline(baseline_file)
  stale = stale_baseline(baseline_file, baseline_header, baseline)
  unless stale.empty?
    abort "#{baseline_file} is out of date for #{stale.join(', ')}. #{regenerate_note(baseline_file, baseline_header['version'])}"
  end
end
released = ARGV[0] || (baseline_file ? nil : latest_released_version)
current = current_version
compared = released || baseline_header["version"]
major_bump = Gem::Version.new(current).segments.first > Gem::Version.new(compared).segments.first
records = load_records

puts "Ruby #{RUBY_VERSION}, fluentd #{FLUENTD_REQUIREMENT}, #{records.size} records"
if baseline_file
  puts "Baseline: #{baseline_file} (#{baseline_header['version']} on Ruby #{baseline_header['ruby']} with fluentd #{baseline_header['fluentd']})"
end
puts "Released: #{released || '(not run)'}, this repository: #{current}"

broken = []
skipped = []
stale = []
written = {}
Dir.mktmpdir do |tmp|
  released_dir = File.join(tmp, "released")
  current_dir = File.join(tmp, "current")
  Dir.mkdir(released_dir)
  Dir.mkdir(current_dir)
  current_env = write_gemfile(current_dir, FLUENTD_REQUIREMENT, %(gem "fluent-plugin-anonymizer", path: #{ROOT.inspect}))
  fluentd = fluentd_version(current_env, current_dir)
  if released
    released_env = write_gemfile(released_dir, fluentd, %(gem "fluent-plugin-anonymizer", #{released.inspect}))
    puts "fluentd #{fluentd_version(released_env, released_dir)} with #{released}, fluentd #{fluentd} with this repository"
  else
    puts "fluentd #{fluentd} with this repository"
  end

  CONFIGS.each do |config|
    name = File.basename(config)
    if released
      # v1.0.0 uses OpenStruct for its parameters in the filter without
      # loading it, so they work on Ruby 3 only if another plugin, such as
      # record_transformer of Fluentd, has loaded it. Load it, to run them.
      # It does not change the output on Ruby 2.7.
      before = run_config(released_env, released_dir, config, records, ["-r", "ostruct"])
      if write_file
        written[config] = before
        puts "#{name}: #{before[:status]}"
        next
      end
      if baseline_file
        kept = baseline[name][1]
        unless kept[:status] == before[:status] &&
               (before[:status] == :error || (same?(kept[:outputs], before[:outputs].sort.to_h) && kept[:logged] == before[:logged]))
          stale << name
          puts "#{name}: the baseline is not the output of #{released}"
        end
      end
    else
      before = baseline[name][1]
    end
    if before[:status] == :error
      skipped << name
      puts "#{name}: skipped: fails with #{compared} too (#{before[:message]})"
      next
    end
    after = run_config(current_env, current_dir, config, records)
    if after[:status] == :error
      broken << name
      puts "#{name}: BROKEN: #{after[:message]}"
      next
    end
    problems, changes = compare_results(records, before, after)
    summary = changes.map { |k, v| "#{k}: #{v}" }.join(", ")
    if problems.empty?
      puts "#{name}: ok (#{before[:outputs].size} records#{summary.empty? ? '' : ', ' + summary})"
    else
      broken << name
      puts "#{name}: BROKEN (#{summary})"
      problems.first(20).each { |p| puts "  #{p}" }
      puts "  ... #{problems.size - 20} more" if problems.size > 20
    end
    (after[:errors] - before[:errors]).uniq.first(3).each { |e| puts "  new error log: #{e}" }
  end

  if write_file
    write_baseline(write_file, released, fluentd, written)
    puts "Wrote #{write_file}"
    exit
  end
end

failed = false
unless stale.empty?
  puts "#{baseline_file} is not the output of #{released} for #{stale.size} configuration(s). #{regenerate_note(baseline_file, released)}"
  failed = true
end
if broken.empty?
  puts "No configuration is broken."
elsif major_bump
  puts "#{broken.size} configuration(s) are broken, which is allowed in a new major version. " \
       "Explain how to change them in the README and the release notes."
else
  puts "#{broken.size} configuration(s) are broken without a new major version."
  failed = true
end
if fail_on_skip && !skipped.empty?
  puts "#{skipped.size} configuration(s) are skipped, which --fail-on-skip does not allow."
  failed = true
end
exit 1 if failed

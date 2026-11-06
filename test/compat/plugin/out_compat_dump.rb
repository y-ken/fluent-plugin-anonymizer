require 'fluent/plugin/output'

module Fluent::Plugin
  # Writes each event as a line COMPAT-RECORD <index> <tag and record in
  # Marshal, in Base64>. Marshal keeps the encoding of each String, which JSON
  # does not. It writes the line with one write, so that a log line of another
  # thread does not split it.
  class CompatDumpOutput < Output
    Fluent::Plugin.register_output('compat_dump', self)

    def process(tag, es)
      es.each do |time, record|
        $stdout.write("COMPAT-RECORD #{time.to_i} #{[Marshal.dump([tag, record])].pack('m0')}\n")
      end
      $stdout.flush
    end
  end
end

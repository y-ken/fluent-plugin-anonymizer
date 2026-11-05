require 'fluent/plugin/input'

module Fluent::Plugin
  # Emits the records of test/compat/records.rb once, each in its own event
  # with the index of the record as the time, so that the check can match an
  # output record to its input even if Fluentd drops another record. Then it
  # writes a line COMPAT-EMITTED, after which no record is output, because the
  # outputs of the configurations are not buffered. A record for which Fluentd
  # raises an error is not output.
  class CompatRecordsInput < Input
    Fluent::Plugin.register_input('compat_records', self)
    helpers :timer

    config_param :tag, :string

    def start
      super
      timer_execute(:compat_records, 0.5, repeat: false) do
        path = File.expand_path('../records.rb', __dir__)
        records = TOPLEVEL_BINDING.eval(File.read(path, encoding: 'UTF-8'), path)
        records.each_with_index do |record, i|
          begin
            router.emit(@tag, Fluent::EventTime.new(i), record)
          rescue => e
            # v1.0.0 raises for some records. Go on with the next record.
            log.warn "record #{i} raised #{e.class}"
          end
        end
        $stdout.write("COMPAT-EMITTED #{records.size}\n")
        $stdout.flush
      end
    end
  end
end

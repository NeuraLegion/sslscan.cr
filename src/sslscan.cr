require "xml"
require "log"
require "./sslscan/entity"
require "./sslscan/entities/*"
require "./sslscan/*"

module SSLScan
  extend self

  extend Parser
  extend Scanner

  Log = ::Log.for(self)

  def version : String
    document = run_xml(%w[--version])
    document =
      find_document(document)
    document["version"]
  end

  protected def run(args : Array(String)) : String
    command = Process.find_executable("sslscan")
    raise "Cannot find 'sslscan' executable" unless command

    Log.debug &.emit("Running sslscan", {
      command: command,
      args:    args,
    })

    output = IO::Memory.new
    error = IO::Memory.new

    start_time = Time.monotonic
    status =
      Process.run(command, args, output: output, error: error)
    elapsed = Time.monotonic - start_time

    Log.debug &.emit("Finished running sslscan", {
      elapsed: elapsed.to_s,
      status:  status.exit_status,
      stdout:  output.to_s.presence,
      stderr:  error.to_s.presence,
    })

    raise error.to_s.chomp unless status.success?

    output.to_s.chomp
  end

  protected def run_xml(args : Array(String)) : XML::Node
    args = %w[--xml=-].concat(args)
    output = run(args)
    XML.parse(output)
  end
end

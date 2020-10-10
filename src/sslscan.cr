require "xml"
require "./sslscan/entities/*"
require "./sslscan/*"

module SSLScan
  extend self
  extend Parser

  def version : String
    document = run_xml(%w[--version])
    document =
      find_document(document)
    document["version"]
  end

  def detect(host : String, port : Int32? = nil, http = false, client_ciphers = false, times = false) : Report
    host += ":#{port}" if port

    args = %w[]
    args << "--http" if http
    args << "--show-ciphers" if client_ciphers
    args << "--show-times" if times
    args << host

    document = run_xml(args)
    result = parse(document)

    case result
    in Test  then Report.new(result)
    in Error then raise result
    end
  end

  protected def run(args : Array(String)) : String
    output = IO::Memory.new
    error = IO::Memory.new

    status =
      Process.run("sslscan", args, output: output, error: error)

    raise error.to_s.chomp unless status.success?

    output.to_s.chomp
  end

  protected def run_xml(args : Array(String)) : XML::Node
    args = %w[--xml=-].concat(args)
    output = run(args)
    XML.parse(output)
  end
end

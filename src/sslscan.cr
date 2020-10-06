require "xml"
require "./sslscan/entities/*"
require "./sslscan/*"

module SSLScan
  extend self
  extend Parser

  def version : String
    document = run_xml("--version")
    document =
      find_document(document)
    document["version"]
  end

  def detect(host : String, port : Int32? = nil) : Report
    document = run_xml(host + (port && ":#{port}").to_s)
    result = parse(document)

    case result
    in Test  then Report.new(result)
    in Error then raise result
    end
  end

  protected def run(*args) : String
    output = IO::Memory.new
    error = IO::Memory.new

    status =
      Process.run("sslscan", args, output: output, error: error)

    raise error.to_s.chomp unless status.success?

    output.to_s.chomp
  end

  protected def run_xml(*args) : XML::Node
    output = run("--xml=-", *args)
    XML.parse(output)
  end
end

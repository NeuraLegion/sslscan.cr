require "../spec_helper"

module TestScanner
  extend self
  include SSLScan::Scanner

  def run_xml(args)
    fixture =
      case args
      when .includes?("foo.bar")
        XML.parse <<-XML
          <?xml version="1.0" encoding="UTF-8"?>
          <foo>
            <bar/>
          </foo>
          XML
      when .includes?("wrong.bar")
        "error"
      else
        show_ciphers = args.includes?("--show-ciphers")
        show_times = args.includes?("--show-times")
        flags =
          case {show_ciphers, show_times}
          when {true, true}  then "-with-ciphers-and-times"
          when {true, false} then "-with-ciphers"
          when {false, true} then "-with-times"
          end
        "nexploit.app#{flags}"
      end

    return fixture if fixture.is_a?(XML::Node)
    xml_fixture("#{fixture}.xml")
  end
end

Spectator.describe SSLScan::Scanner do
  describe ".scan" do
    it "raises regular Exception for unknown elements" do
      expect { TestScanner.scan("foo.bar") }.to raise_error
    end

    it "returns Error object for error output" do
      expect { TestScanner.scan("wrong.bar") }.to raise_error(SSLScan::Error)
    end

    it "returns Report object for regular output" do
      expect { TestScanner.scan("nexploit.app") }.to be_a(SSLScan::Report)
    end
  end
end

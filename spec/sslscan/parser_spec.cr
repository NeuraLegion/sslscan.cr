require "../spec_helper"

module TestParser
  extend self
  include SSLScan::Parser

  def parse?(node)
    super
  end

  def parse(node)
    super
  end
end

Spectator.describe SSLScan::Parser do
  let(fixture) { xml_fixture("app.neuralegion.com.xml") }
  let(error_fixture) { xml_fixture("error.xml") }
  let(dummy_fixture) do
    XML.parse <<-XML
      <?xml version="1.0" encoding="UTF-8"?>
      <foo>
        <bar/>
      </foo>
      XML
  end

  describe ".parse?" do
    it "returns Test object for regular output" do
      expect(TestParser.parse?(fixture)).to be_a(SSLScan::Test)
    end

    it "returns Error object for error output" do
      expect(TestParser.parse?(error_fixture)).to be_a(SSLScan::Error)
    end

    it "returns nil for unknown elements" do
      expect(TestParser.parse?(dummy_fixture)).to be_nil
    end
  end

  describe ".parse" do
    it "raises for unknown elements" do
      expect { TestParser.parse(dummy_fixture) }.to raise_error
    end
  end
end

require "./spec_helper"

Spectator.describe SSLScan do
  describe ".version" do
    mock SSLScan do
      stub run_xml(args : Array(String)) do
        xml_fixture("version.xml")
      end
    end

    it "returns version string from document[version] attribute" do
      expect(SSLScan.version).to eq "2.0.4-static"
    end
  end
end

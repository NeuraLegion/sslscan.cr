module SSLScan
  record Heartbleed, ssl_version : String, vulnerable : Bool do
    include Entity
    getter? vulnerable

    def issue_context : String?
      ssl_version
    end
  end
end

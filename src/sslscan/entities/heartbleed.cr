module SSLScan
  record Heartbleed, ssl_version : String, vulnerable : Bool do
    getter? vulnerable
  end
end

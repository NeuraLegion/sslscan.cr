module SSLScan
  record ConnectionSignatureAlgorithm, ssl_version : String, name : String, id : String do
    include Entity

    def issue_context : String?
      name
    end
  end
end

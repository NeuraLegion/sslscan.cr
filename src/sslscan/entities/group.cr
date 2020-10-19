module SSLScan
  record Group, ssl_version : String, bits : Int32, name : String, id : String do
    include Entity

    def issue_context : String?
      name
    end
  end
end

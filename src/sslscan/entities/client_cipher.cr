module SSLScan
  record ClientCipher, cipher : String, provider : String do
    include Entity

    def issue_context : String?
      cipher
    end
  end
end

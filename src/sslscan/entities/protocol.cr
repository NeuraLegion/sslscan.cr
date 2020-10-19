module SSLScan
  struct Protocol
    include Entity

    enum Type
      SSL
      TLS
    end

    getter type : Type
    getter version : String
    getter? enabled : Bool

    def initialize(
      @type : Type,
      @version,
      @enabled
    )
    end

    def version_verbose : String
      "#{type}v#{version}"
    end

    def issue_context : String?
      version_verbose
    end
  end
end

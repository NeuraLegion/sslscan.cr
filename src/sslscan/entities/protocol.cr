module SSLScan
  struct Protocol
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
  end
end

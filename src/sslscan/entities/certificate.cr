module SSLScan
  class Certificate
    include Entity

    enum Type
      Short
      Full
    end

    struct PK
      enum Type
        Unknown
        RSA
        DSA
        EC
      end

      getter? error : Bool
      getter type : Type
      getter curve_name : String?
      getter bits : Int32?

      def initialize(
        @error,
        @type : Type,
        @curve_name,
        @bits
      )
      end
    end

    getter type : Type = :short
    getter signature_algorithm : String?
    getter pk : PK?
    getter subject : String?
    getter alt_names : Array(String)?
    getter issuer : String?
    getter? self_signed : Bool?
    getter not_valid_before : Time
    getter not_valid_after : Time
    getter? expired : Bool

    def initialize(
      @signature_algorithm,
      @pk,
      @subject,
      @alt_names,
      @issuer,
      @self_signed,
      @not_valid_before,
      @not_valid_after,
      @expired
    )
    end

    def issue_context : String?
      subject
    end
  end
end

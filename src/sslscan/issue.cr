module SSLScan
  struct Issue
    enum Type
      UnsecureRenegotiation
      CompressionEnabled
      Heartbleed
      NullCipher
      WeakCipher
      WeakProtocol
      UnsupportedProtocol
      SelfSignedCertificate
      ExpiredCertificate
      WeakCertificate
      WeakGroup
      WeakConnectionSignatureAlgorithm
    end

    getter type : Type
    getter context : String?

    def initialize(@type : Type, @context = nil)
    end

    def_equals @type, @context
  end
end

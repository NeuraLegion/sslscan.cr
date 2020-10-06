module SSLScan
  class Test
    getter host : String
    getter sni_name : String
    getter port : Int32
    getter protocols : Array(Protocol)
    getter client_ciphers : Array(ClientCipher)
    getter renegotiation : Renegotiation
    getter compression : Compression?
    getter heartbleed : Array(Heartbleed)
    getter ciphers : Array(Cipher)
    getter certificates : Array(Certificate)
    getter groups : Array(Group)
    getter connection_signature_algorithms : Array(ConnectionSignatureAlgorithm)

    def initialize(
      @host,
      @sni_name,
      @port,
      @protocols,
      @client_ciphers,
      @renegotiation,
      @compression,
      @heartbleed,
      @ciphers,
      @certificates,
      @groups,
      @connection_signature_algorithms
    )
    end
  end
end

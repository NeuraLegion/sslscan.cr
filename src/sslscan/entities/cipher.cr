module SSLScan
  class Cipher
    include Entity

    enum Status
      Accepted
      Preferred
    end

    enum Strength
      Null
      Anonymous
      Weak
      Medium
      Strong
      Acceptable
    end

    getter status : Status
    getter ssl_version : String
    getter bits : Int32
    getter cipher : String
    getter id : String
    getter strength : Strength
    getter curve : String?
    getter dhe_bits : Int32?
    getter ecdhe_bits : Int32?
    getter time : Time::Span?

    def initialize(
      @status : Status,
      @ssl_version,
      @bits,
      @cipher,
      @id,
      @strength : Strength,
      @curve,
      @dhe_bits,
      @ecdhe_bits,
      @time
    )
    end

    def issue_context : String?
      cipher
    end
  end
end

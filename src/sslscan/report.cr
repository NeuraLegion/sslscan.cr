module SSLScan
  class Report
    STRONG_PROTOCOLS =
      {"TLSv1.3"}

    WEAK_PROTOCOLS =
      {"SSLv2", "SSLv3", "TLSv1.0"}

    WEAK_CIPHERS = {
      "RC4",
      "DES",           # Compromised by the American NSA
      "_SM4_",         # Developed by Chinese government
      "_GOSTR341112_", # Developed by Russian government
    }

    WEAK_GROUPS = {
      "sect163k1",
      "sect163r1",
      "sect163r2",
      "sect193r1",
      "sect193r2",
      "secp160k1",
      "secp160r1",
      "secp160r2",
      "secp192k1",
      "secp192r1",
    }

    WEAK_SIGNATURE_ALGORITHMS = {
      "md5", "sha1", "any",
      "rsa_pkcs1_nohash",
      "dsa_nohash",
      "ecdsa_nohash",
      "rsa_pkcs1_sha224",
      "dsa_sha224",
      "ecdsa_sha224",
      "dsa_sha256",
      "dsa_sha384",
      "dsa_sha512",
    }

    getter test : Test
    getter issues = [] of Issue

    def initialize(@test)
      add_issues(test.renegotiation)
      add_issues(test.compression)
      add_issues(test.heartbleed)
      add_issues(test.ciphers)
      add_issues(test.protocols)
      add_issues(test.certificates)
      add_issues(test.groups)
      add_issues(test.connection_signature_algorithms)

      issues.uniq!
    end

    protected def add_issue(severity : Issue::Severity, type : String, context : String? = nil)
      issues << Issue.new(severity, type, context)
    end

    protected def add_issue(severity : Issue::Severity, entity : Entity, type : String | Symbol)
      add_issue(severity, "#{entity.issue_namespace}.#{type}", entity.issue_context)
    end

    protected def add_issues(entity : Nil)
    end

    protected def add_issues(renegotiation : Renegotiation)
      if renegotiation.supported?
        if renegotiation.secure?
          add_issue :low, renegotiation, :secure
        else
          add_issue :high, renegotiation, :unsecure
        end
      end
    end

    protected def add_issues(compression : Compression)
      if compression.supported?
        add_issue :high, compression, :enabled
      else
        add_issue :low, compression, :disabled
      end
    end

    protected def add_issues(heartbleeds : Array(Heartbleed))
      heartbleeds.each do |heartbleed|
        if heartbleed.vulnerable?
          add_issue :high, heartbleed, :vulnerable
        else
          add_issue :low, heartbleed, :invulnerable
        end
      end
    end

    protected def add_issues(ciphers : Array(Cipher))
      ciphers.each do |cipher|
        name = cipher.cipher.upcase

        if cipher.strength.null?
          add_issue :high, cipher, "strength.null"
        end
        if cipher.strength.weak? || cipher.bits < 56
          add_issue :high, cipher, "strength.weak"
        end
        if WEAK_CIPHERS.any? { |v| name[v]? }
          add_issue :high, cipher, "strength.weak"
        end
      end
    end

    protected def add_issues(protocols : Array(Protocol))
      protocols.each do |protocol|
        case protocol.version_verbose
        when .in?(WEAK_PROTOCOLS)
          if protocol.enabled?
            add_issue :high, protocol, :enabled
          else
            add_issue :low, protocol, :disabled
          end
        when .in?(STRONG_PROTOCOLS)
          if protocol.enabled?
            add_issue :low, protocol, :enabled
          else
            add_issue :high, protocol, :disabled
          end
        end
      end
    end

    protected def add_issues(certificates : Array(Certificate))
      certificates.each do |certificate|
        add_issue :high, certificate, :self_signed if certificate.self_signed?
        add_issue :high, certificate, :expired if certificate.expired?

        if (pk = certificate.pk) && (bits = pk.bits)
          case pk.type
          when .rsa?
            add_issue :high, certificate, "strength.weak" if bits < 2048
          when .ec?
            add_issue :high, certificate, "strength.weak" if bits < 128
          end
        end
      end
    end

    protected def add_issues(groups : Array(Group))
      groups.each do |group|
        name = group.name.downcase

        add_issue :high, group, "strength.weak" if group.bits < 128
        add_issue :high, group, "strength.weak" if WEAK_GROUPS.any? { |v| name[v]? }
      end
    end

    protected def add_issues(connection_signature_algorithms : Array(ConnectionSignatureAlgorithm))
      connection_signature_algorithms.each do |connection_signature_algorithm|
        name = connection_signature_algorithm.name.downcase

        if WEAK_SIGNATURE_ALGORITHMS.any? { |v| name[v]? }
          add_issue :high, connection_signature_algorithm, "strength.weak"
        end
      end
    end
  end
end

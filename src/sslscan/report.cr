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

    protected def add_issue(severity : Issue::Severity, type : String, context : String? = nil)
      issues << Issue.new(severity, type, context)
    end

    # ameba:disable Metrics/CyclomaticComplexity
    def initialize(@test)
      if test.renegotiation.supported?
        if test.renegotiation.secure?
          add_issue :low, "renegotiation.secure"
        else
          add_issue :high, "renegotiation.unsecure"
        end
      end

      if compression = test.compression
        if compression.supported?
          add_issue :high, "compression.enabled"
        else
          add_issue :low, "compression.disabled"
        end
      end

      test.heartbleed.each do |heartbleed|
        if heartbleed.vulnerable?
          add_issue :high, "heartbleed.vulnerable", heartbleed.ssl_version
        else
          add_issue :low, "heartbleed.invulnerable", heartbleed.ssl_version
        end
      end

      test.ciphers.each do |cipher|
        name = cipher.cipher

        if cipher.strength.null?
          add_issue :high, "cipher.strength.null", name
        end
        if cipher.strength.weak? || cipher.bits < 56
          add_issue :high, "cipher.strength.weak", name
        end
        if WEAK_CIPHERS.any? { |v| name.upcase[v]? }
          add_issue :high, "cipher.strength.weak", name
        end
      end

      test.protocols.each do |protocol|
        version = "#{protocol.type.to_s.upcase}v#{protocol.version}"

        case version
        when .in?(WEAK_PROTOCOLS)
          if protocol.enabled?
            add_issue :high, "protocol.enabled", version
          else
            add_issue :low, "protocol.disabled", version
          end
        when .in?(STRONG_PROTOCOLS)
          if protocol.enabled?
            add_issue :low, "protocol.enabled", version
          else
            add_issue :high, "protocol.disabled", version
          end
        end
      end

      test.certificates.each do |certificate|
        subject = certificate.subject

        add_issue :high, "certificate.self_signed", subject if certificate.self_signed?
        add_issue :high, "certificate.expired", subject if certificate.expired?

        next unless pk = certificate.pk
        next unless bits = pk.bits

        case pk.type
        when .rsa?
          add_issue :high, "certificate.strength.weak", subject if bits < 2048
        when .ec?
          add_issue :high, "certificate.strength.weak", subject if bits < 128
        end
      end

      test.groups.each do |group|
        name = group.name

        add_issue :high, "group.strength.weak", name if group.bits < 128
        add_issue :high, "group.strength.weak", name if WEAK_GROUPS.any? { |v| name.downcase[v]? }
      end

      test.connection_signature_algorithms.each do |csa|
        name = csa.name

        if WEAK_SIGNATURE_ALGORITHMS.any? { |v| name.downcase[v]? }
          add_issue :high, "connection_signature_algorithm.strength.weak", name
        end
      end

      issues.uniq!
    end
  end
end

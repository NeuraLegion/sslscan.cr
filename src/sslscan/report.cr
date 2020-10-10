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

    protected def add_issue(type : Issue::Type, context : String? = nil)
      issues << Issue.new(type, context)
    end

    # ameba:disable Metrics/CyclomaticComplexity
    def initialize(@test)
      if test.renegotiation.supported? && !test.renegotiation.secure?
        add_issue :unsecure_renegotiation
      end

      if test.compression.try(&.supported?)
        add_issue :compression_enabled
      end

      test.heartbleed.each do |heartbleed|
        if heartbleed.vulnerable?
          add_issue :heartbleed, heartbleed.ssl_version
        end
      end

      test.ciphers.each do |cipher|
        name = cipher.cipher

        if cipher.strength.null?
          add_issue :null_cipher, name
        end
        if cipher.strength.weak? || cipher.bits < 56
          add_issue :weak_cipher, name
        end
        if WEAK_CIPHERS.any? { |v| name.upcase[v]? }
          add_issue :weak_cipher, name
        end
      end

      test.protocols.each do |protocol|
        version = "#{protocol.type.to_s.upcase}v#{protocol.version}"

        if version.in?(WEAK_PROTOCOLS) && protocol.enabled?
          add_issue :weak_protocol, version
        end
        if version.in?(STRONG_PROTOCOLS) && !protocol.enabled?
          add_issue :unsupported_protocol, version
        end
      end

      test.certificates.each do |certificate|
        subject = certificate.subject

        add_issue :self_signed_certificate, subject if certificate.self_signed?
        add_issue :expired_certificate, subject if certificate.expired?

        next unless pk = certificate.pk
        next unless bits = pk.bits

        case pk.type
        when .rsa?
          add_issue :weak_certificate, subject if bits < 2048
        when .ec?
          add_issue :weak_certificate, subject if bits < 128
        end
      end

      test.groups.each do |group|
        name = group.name

        add_issue :weak_group, name if group.bits < 128
        add_issue :weak_group, name if WEAK_GROUPS.any? { |v| name.downcase[v]? }
      end

      test.connection_signature_algorithms.each do |csa|
        name = csa.name

        if WEAK_SIGNATURE_ALGORITHMS.any? { |v| name.downcase[v]? }
          add_issue :weak_connection_signature_algorithm, name
        end
      end

      issues.uniq!
    end
  end
end

module SSLScan
  class Report
    WEAK_CIPHERS =
      {"RC4", "DES", "_SM4_", "_GOSTR341112_"}

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
    getter issues = [] of {Symbol, String?}

    # ameba:disable Metrics/CyclomaticComplexity
    def initialize(@test)
      if test.renegotiation.supported? && !test.renegotiation.secure?
        issues << {:unsecure_renegotiation, nil}
      end

      if test.compression.try(&.supported?)
        issues << {:compression_enabled, nil}
      end

      test.heartbleed.each do |heartbleed|
        if heartbleed.vulnerable?
          issues << {:heartbleed, heartbleed.ssl_version}
        end
      end

      test.ciphers.each do |cipher|
        name = cipher.cipher
        if cipher.strength.null?
          issues << {:null_cipher, name}
        end
        if cipher.strength.weak? || cipher.bits < 56
          issues << {:weak_cipher, name}
        end
        if WEAK_CIPHERS.any? { |v| name.upcase[v]? }
          issues << {:weak_cipher, name}
        end
      end

      test.protocols.each do |protocol|
        version = protocol.version
        case protocol.type
        in .ssl?
          if version.in?("2", "3") && protocol.enabled?
            issues << {:weak_protocol, "SSLv" + version}
          end
        in .tls?
          if version.in?("1.0") && protocol.enabled?
            issues << {:weak_protocol, "TLSv" + version}
          end
          if version.in?("1.3") && !protocol.enabled?
            issues << {:unsupported_protocol, "TLSv" + version}
          end
        end
      end

      test.certificates.each do |certificate|
        issues << {:self_signed_certificate, certificate.subject} if certificate.self_signed?
        issues << {:expired_certificate, certificate.subject} if certificate.expired?

        next unless pk = certificate.pk
        next unless bits = pk.bits

        case pk.type
        when .rsa?
          issues << {:weak_certificate, certificate.subject} if bits < 2048
        when .ec?
          issues << {:weak_certificate, certificate.subject} if bits < 128
        end
      end

      test.groups.each do |group|
        name = group.name
        issues << {:weak_group, name} if group.bits < 128
        issues << {:weak_group, name} if WEAK_GROUPS.any? { |v| name.downcase[v]? }
      end

      test.connection_signature_algorithms.each do |csa|
        name = csa.name
        if %w[md5 sha1 any].any? { |v| name.downcase[v]? }
          issues << {:weak_connection_signature_algorithm, name}
        end
        if name.downcase.in?(WEAK_SIGNATURE_ALGORITHMS)
          issues << {:weak_connection_signature_algorithm, name}
        end
      end

      issues.uniq!
    end
  end
end

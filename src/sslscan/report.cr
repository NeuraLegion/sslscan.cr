module SSLScan
  class Report
    getter test : Test

    def initialize(@test)
    end

    # ameba:disable Metrics/CyclomaticComplexity
    def issues
      issues = Set(Symbol | Tuple(Symbol, String)).new

      if test.renegotiation.supported? && !test.renegotiation.secure?
        issues << :unsecure_renegotiation
      end

      if test.compression.try(&.supported?)
        issues << :compression_enabled
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
        if %w[RC4 DES _SM4_ _GOSTR341112_].any? { |v| name.upcase[v]? }
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
            issues << {:missing_protocol, "TLSv" + version}
          end
        end
      end

      test.certificates.each do |certificate|
        issues << :self_signed_certificate if certificate.self_signed?
        issues << :expired_certificate if certificate.expired?

        next unless pk = certificate.pk
        next unless bits = pk.bits

        case pk.type
        when .rsa?
          issues << :weak_certificate if bits < 2048
        when .ec?
          issues << :weak_certificate if bits < 112
        end
      end

      test.groups.each do |group|
        issues << {:weak_group, group.name} if group.bits < 128
      end

      test.connection_signature_algorithms.each do |csa|
        name = csa.name
        if %w[md5 sha1 any].any? { |v| name.downcase[v]? }
          issues << {:weak_connection_signature_algorithm, name}
        end
      end

      issues
    end
  end
end

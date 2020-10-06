module SSLScan
  class Report
    getter test : Test

    def initialize(@test)
    end

    def issues
      issues = Set(Symbol | Tuple(Symbol, String)).new

      issues << :unsecure_renegotiation if !test.renegotiation.secure?
      issues << :heartbleed if test.heartbleed.any?(&.vulnerable?)

      test.ciphers.each do |cipher|
        issues << {:null_cipher, cipher.cipher} if cipher.strength.null?
        issues << {:weak_cipher, cipher.cipher} if cipher.strength.weak? ||
                                                   cipher.bits < 56
      end

      test.protocols.each do |protocol|
        issues << {:weak_protocol, protocol.version} if protocol.type.ssl? &&
                                                        protocol.version.in?("2", "3") &&
                                                        protocol.enabled?
      end

      test.certificates.each do |certificate|
        issues << :self_signed_certificate if certificate.self_signed?
        issues << :expired_certificate if certificate.expired?

        pk = certificate.pk
        case pk.type
        when .rsa?
          issues << :weak_certificate if pk.bits.try(&.<(2048))
        when .ec?
          issues << :weak_certificate if pk.bits.try(&.<(112))
        end
      end

      test.groups.each do |group|
        issues << {:weak_group, group.name} if group.bits < 112
      end

      test.connection_signature_algorithms.each do |csa|
        issues << {:weak_connection_signature_algorithm, csa.name} if csa.name["md5"]? ||
                                                                      csa.name["sha1"]?
      end

      issues
    end
  end
end

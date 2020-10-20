module SSLScan
  class Report
    # NOTE: Upper-cased partial matches
    CIPHER_LEVELS = {
      "EXP"           => :weak,
      "RC4"           => :medium,
      "DES"           => :medium, # Compromised by the American NSA
      "_SM4_"         => :medium, # Developed by Chinese government
      "_GOSTR341112_" => :medium, # Developed by Russian government
      "CHACHA20"      => :strong,
      "GCM"           => :strong,
    } of String => Entity::Strength

    # NOTE: Exact matches
    PROTOCOL_LEVELS = {
      "SSLv2"   => :weak,
      "SSLv3"   => :weak,
      "TLSv1.0" => :medium,
      "TLSv1.3" => :strong,
    } of String => Entity::Strength

    # NOTE: Lower-cased partial matches
    GROUP_LEVELS = {
      "sect163k1" => :weak,
      "sect163r1" => :weak,
      "sect163r2" => :weak,
      "sect193r1" => :weak,
      "sect193r2" => :weak,
      "secp160r1" => :weak,
      "secp160r2" => :weak,
      "secp192k1" => :weak,
      "secp192r1" => :weak,
      "secp256k1" => :strong,
      "x25519"    => :strong,
      "x448"      => :strong,
    } of String => Entity::Strength

    # NOTE: Lower-cased partial matches
    SIGNATURE_ALGORITHM_LEVELS = {
      "any"              => :weak,
      "md5"              => :weak,
      "sha1"             => :weak,
      "rsa_pkcs1_nohash" => :weak,
      "dsa_nohash"       => :weak,
      "ecdsa_nohash"     => :weak,
      "rsa_pkcs1_md5"    => :weak,
      "dsa_md5"          => :weak,
      "ecdsa_md5"        => :weak,
      "rsa_pkcs1_sha1"   => :weak,
      "dsa_sha1"         => :weak,
      "ecdsa_sha1"       => :weak,
      "dsa_sha224"       => :weak,
      "dsa_sha256"       => :weak,
      "dsa_sha384"       => :weak,
      "dsa_sha512"       => :weak,
      "rsa_pkcs1_sha224" => :medium,
      "ecdsa_sha224"     => :medium,
      "ed25519"          => :strong,
      "ed448"            => :strong,
    } of String => Entity::Strength

    getter test : Test
    getter issues = Set(Issue).new

    def initialize(@test)
      add_issues(test.renegotiation)
      add_issues(test.compression)
      add_issues(test.heartbleed)
      add_issues(test.ciphers)
      add_issues(test.protocols)
      add_issues(test.certificates)
      add_issues(test.groups)
      add_issues(test.connection_signature_algorithms)
    end

    protected def entity_strength_to_issue_severity(strength : Entity::Strength) : Issue::Severity
      case strength
      in .weak?   then Issue::Severity::High
      in .medium? then Issue::Severity::Medium
      in .strong? then Issue::Severity::Low
      end
    end

    protected def add_issue(severity : Issue::Severity, type : String, context : String? = nil)
      issues << Issue.new(severity, type, context)
    end

    protected def add_issue(severity : Issue::Severity, entity : Entity, type : String | Symbol)
      add_issue(severity, "#{entity.issue_namespace}.#{type}", entity.issue_context)
    end

    protected def add_issue(entity : Entity, strength : Entity::Strength)
      add_issue \
        entity_strength_to_issue_severity(strength),
        entity,
        "strength.#{strength.to_s.downcase}"
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
        add_issue cipher, :weak if cipher.bits < 56

        case cipher.strength
        when .null?   then add_issue cipher, :weak
        when .weak?   then add_issue cipher, :weak
        when .medium? then add_issue cipher, :medium
        when .strong? then add_issue cipher, :strong
        end
        CIPHER_LEVELS.find(&.first[cipher.cipher.upcase]?).try do |_, strength|
          add_issue cipher, strength
        end
      end
    end

    protected def add_issues(protocols : Array(Protocol))
      protocols.each do |protocol|
        next unless strength = PROTOCOL_LEVELS[protocol.version_verbose]?
        case strength
        in .weak?
          if protocol.enabled?
            add_issue :high, protocol, :enabled
          else
            add_issue :low, protocol, :disabled
          end
        in .medium?
          if protocol.enabled?
            add_issue :medium, protocol, :enabled
          end
        in .strong?
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
            add_issue certificate, :weak if bits < 2048
          when .ec?
            add_issue certificate, :weak if bits < 128
          end
        end
      end
    end

    protected def add_issues(groups : Array(Group))
      groups.each do |group|
        add_issue group, :weak if group.bits < 128

        GROUP_LEVELS.find(&.first[group.name.downcase]?).try do |_, strength|
          add_issue group, strength
        end
      end
    end

    protected def add_issues(connection_signature_algorithms : Array(ConnectionSignatureAlgorithm))
      connection_signature_algorithms.each do |connection_signature_algorithm|
        name = connection_signature_algorithm.name.downcase

        SIGNATURE_ALGORITHM_LEVELS.find(&.first[name]?).try do |_, strength|
          add_issue connection_signature_algorithm, strength
        end
      end
    end
  end
end

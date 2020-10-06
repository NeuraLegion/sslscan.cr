module SSLScan
  module Parser
    protected def parse(node : XML::Node) : Test | Error
      parse?(node) || raise "Couldn't parse the document"
    end

    protected def parse?(node : XML::Node) : Test | Error?
      return unless document = find_document?(node)
      return unless child = find_main_node?(document)

      case child.name
      when "ssltest"
        build_test(child)
      when "error"
        Error.new(child.content)
      end
    end

    protected def find_document(node : XML::Node) : XML::Node
      find_document?(node) || raise "Couldn't find the main document node"
    end

    protected def find_document?(node : XML::Node) : XML::Node?
      return unless child = node.first_element_child
      return unless child.name == "document"
      child
    end

    protected def find_main_node?(node : XML::Node) : XML::Node?
      return unless child = node.first_element_child
      return unless child.name.in?("ssltest", "error")
      child
    end

    @[AlwaysInline]
    protected def find_child(node : XML::Node, name : String)
      node.children.find(&.name.==(name))
    end

    @[AlwaysInline]
    protected def find_children(node : XML::Node, name : String)
      node.children.select(&.name.==(name))
    end

    protected def build_renegotiation(ssltest : XML::Node) : Renegotiation
      node = get_child(ssltest, "renegotiation")
      Renegotiation.new(
        supported: node["supported"] == "1",
        secure: node["secure"] == "1",
      )
    end

    @[AlwaysInline]
    protected def map_children(ssltest : XML::Node, name : String)
      find_children(ssltest, name).map do |node|
        yield node
      end
    end

    protected def build_protocols(ssltest : XML::Node) : Array(Protocol)
      map_children(ssltest, "protocol") do |node|
        Protocol.new(
          type: Protocol::Type.parse(node["type"]),
          version: node["version"],
          enabled: node["enabled"] == "1",
        )
      end
    end

    protected def build_heartbleed(ssltest : XML::Node) : Array(Heartbleed)
      map_children(ssltest, "heartbleed") do |node|
        Heartbleed.new(
          ssl_version: node["sslversion"],
          vulnerable: node["vulnerable"] == "1",
        )
      end
    end

    protected def build_ciphers(ssltest : XML::Node) : Array(Cipher)
      map_children(ssltest, "cipher") do |node|
        Cipher.new(
          status: Cipher::Status.parse(node["status"]),
          ssl_version: node["sslversion"],
          bits: node["bits"].to_i,
          cipher: node["cipher"],
          id: node["id"],
          strength: Cipher::Strength.parse(node["strength"]),
          curve: node["curve"]?,
          ecdhe_bits: node["ecdhebits"]?.try(&.to_i),
        )
      end
    end

    @[AlwaysInline]
    protected def get_child(node : XML::Node, name : String) : XML::Node
      find_child(node, name).not_nil!
    end

    @[AlwaysInline]
    protected def get_child_content(node : XML::Node, name : String) : String
      get_child(node, name).content
    end

    protected def build_certificate(node : XML::Node) : Certificate
      pk = get_child(node, "pk")
      signature_algorithm = get_child_content(node, "signature-algorithm")
      subject = get_child_content(node, "subject")
      alt_names = get_child_content(node, "altnames")
      issuer = get_child_content(node, "issuer")
      self_signed = get_child_content(node, "self-signed")
      not_valid_before = get_child_content(node, "not-valid-before")
      not_valid_after = get_child_content(node, "not-valid-after")
      expired = get_child_content(node, "expired")

      Certificate.new(
        signature_algorithm: signature_algorithm,
        pk: Certificate::PK.new(
          error: pk["error"] == "true",
          type: Certificate::PK::Type.parse(pk["type"]),
          curve_name: pk["curve_name"]?,
          bits: pk["bits"]?.try(&.to_i),
        ),
        subject: subject,
        alt_names: alt_names.split(/,\s*/),
        issuer: issuer,
        self_signed: self_signed == "true",
        not_valid_before: Time.parse_utc(not_valid_before, "%b %e %H:%M:%S %Y GMT"),
        not_valid_after: Time.parse_utc(not_valid_after, "%b %e %H:%M:%S %Y GMT"),
        expired: expired == "true",
      )
    end

    protected def build_certificates(ssltest : XML::Node) : Array(Certificate)
      certificates = get_child(ssltest, "certificates")
      map_children(certificates, "certificate") do |node|
        build_certificate(node)
      end
    end

    protected def build_groups(ssltest : XML::Node) : Array(Group)
      map_children(ssltest, "group") do |node|
        Group.new(
          ssl_version: node["sslversion"],
          bits: node["bits"].to_i,
          name: node["name"],
          id: node["id"],
        )
      end
    end

    protected def build_csas(ssltest : XML::Node) : Array(ConnectionSignatureAlgorithm)
      map_children(ssltest, "connection-signature-algorithm") do |node|
        ConnectionSignatureAlgorithm.new(
          ssl_version: node["sslversion"],
          name: node["name"],
          id: node["id"],
        )
      end
    end

    protected def build_test(ssltest : XML::Node) : Test
      renegotiation = build_renegotiation(ssltest)
      protocols = build_protocols(ssltest)
      heartbleed = build_heartbleed(ssltest)
      ciphers = build_ciphers(ssltest)
      certificates = build_certificates(ssltest)
      groups = build_groups(ssltest)
      csas = build_csas(ssltest)

      Test.new(
        host: ssltest["host"],
        sni_name: ssltest["sniname"],
        port: ssltest["port"].to_i,
        protocols: protocols,
        renegotiation: renegotiation,
        heartbleed: heartbleed,
        ciphers: ciphers,
        certificates: certificates,
        groups: groups,
        connection_signature_algorithms: csas,
      )
    end
  end
end

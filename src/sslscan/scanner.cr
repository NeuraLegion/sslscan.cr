module SSLScan
  module Scanner
    include Parser

    # ameba:disable Metrics/CyclomaticComplexity
    def scan(host : String, port : Int32? = nil, sni_name : String? = nil, ip_version : Symbol? = nil, client_ciphers : Bool = false, times : Bool = false, sleep : Time::Span? = nil, timeout : Time::Span? = nil) : Report
      host += ":#{port}" if port

      args = %w[--no-colour]
      args << "--sni-name=#{sni_name}" if sni_name
      case ip_version
      when :ipv4 then args << "--ipv4"
      when :ipv6 then args << "--ipv6"
      end
      args << "--show-ciphers" if client_ciphers
      args << "--show-times" if times
      args << "--sleep=#{sleep.total_milliseconds.to_i}" if sleep
      args << "--timeout=#{timeout.total_seconds.to_i}" if timeout
      args << host

      document = run_xml(args)
      result =
        parse(document)

      case result
      in Test  then Report.new(result)
      in Error then raise result
      end
    end
  end
end

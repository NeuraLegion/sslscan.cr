module SSLScan
  module Scanner
    include Parser

    def scan(host : String, port : Int32? = nil, client_ciphers = false, times = false) : Report
      host += ":#{port}" if port

      args = %w[--no-colour]
      args << "--show-ciphers" if client_ciphers
      args << "--show-times" if times
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

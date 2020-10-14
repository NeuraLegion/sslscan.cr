module SSLScan
  struct Issue
    enum Severity
      Low
      Medium
      High
    end

    getter severity : Severity
    getter type : String
    getter context : String?

    def initialize(@severity : Severity, @type, @context = nil)
    end
  end
end

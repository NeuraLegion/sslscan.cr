module SSLScan
  module Entity
    macro included
      def issue_namespace : String
        {{
          @type.name
            .gsub(/SSLScan::/i, "")
            .gsub(/::/, ".")
            .underscore
            .stringify
        }}
      end

      def issue_context : String?
      end
    end
  end
end

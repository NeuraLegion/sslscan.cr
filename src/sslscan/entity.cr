module SSLScan
  module Entity
    enum Strength
      Weak
      Medium
      Strong
    end

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

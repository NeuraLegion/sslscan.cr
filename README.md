# sslscan.cr ![Build Status](https://github.com/NeuraLegion/sslscan.cr/workflows/CI/badge.svg) [![Releases](https://img.shields.io/github/release/NeuraLegion/sslscan.cr.svg)](https://github.com/NeuraLegion/sslscan.cr/releases) [![License](https://img.shields.io/github/license/NeuraLegion/sslscan.cr.svg)](https://github.com/NeuraLegion/sslscan.cr/blob/master/LICENSE)

Crystal shard wrapping [sslscan](https://github.com/rbsec/sslscan) (v2) utility.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     sslscan:
       github: NeuraLegion/sslscan.cr
   ```

2. Run `shards install`

## Usage

```crystal
require "sslscan"

report = SSLScan.scan "github.com" # => #<SSLScan::Report ...>

# Browse the already aggregated issues
report.issues.each do |issue|
  issue.severity # SSLScan::Issue::Severity
  issue.type     # String
  issue.context  # String
end
report.issues.select(&.severity.high?) # => Set{...}

# Or access the test results directly for further inspection
report.test # => #<SSLScan::Test ...>
```

## Contributing

1. Fork it (<https://github.com/NeuraLegion/sslscan.cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Sijawusz Pur Rahnama](https://github.com/Sija) - creator and maintainer

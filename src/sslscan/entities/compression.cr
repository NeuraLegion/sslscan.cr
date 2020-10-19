module SSLScan
  record Compression, supported : Bool do
    include Entity
    getter? supported
  end
end

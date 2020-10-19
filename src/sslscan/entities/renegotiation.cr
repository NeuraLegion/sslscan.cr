module SSLScan
  record Renegotiation, supported : Bool, secure : Bool do
    include Entity
    getter? supported, secure
  end
end

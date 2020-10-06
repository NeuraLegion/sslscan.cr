module SSLScan
  record Renegotiation, supported : Bool, secure : Bool do
    getter? supported, secure
  end
end

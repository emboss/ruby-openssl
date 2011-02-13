require 'openssl'
require 'perftools'

der = File.binread('LTQ.cer')

PerfTools::CpuProfiler.start('profile') do
  1000.times do
    cert = OpenSSL::ASN1.decode(der)
    cert.to_der
  end
end
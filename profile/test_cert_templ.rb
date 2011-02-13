require 'openssl'
require 'test/unit'

class TestCert < Test::Unit::TestCase
  
  def test
    der = File.binread('LTQ.cer')
    1000.times do
      cert = OpenSSL::Certificate.parse(der)
      #cert = OpenSSL::ASN1.decode(der)
      cert.to_der
    end
  end
  
end

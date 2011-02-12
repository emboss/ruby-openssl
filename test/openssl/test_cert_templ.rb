require 'openssl'
require 'test/unit'

class  OpenSSL::TestCertificate < Test::Unit::TestCase

  def test_certificate
    der = File.binread('LTQ.cer')
    1000.times do
      cert = OpenSSL::Certificate.parse(der)
      cert.to_der
    end
  end

end
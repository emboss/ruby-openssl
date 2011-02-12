require_relative 'utils'

class  OpenSSL::TestCertificate < Test::Unit::TestCase

  def test_certificate
    der = File.binread('LTQ.cer')
    cert = OpenSSL::Certificate.parse(der)
    assert_equal(der, cert.to_der)
  end
end
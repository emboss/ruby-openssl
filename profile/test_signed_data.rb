require 'openssl'
require 'test/unit'
require 'pp'

class TestCert < Test::Unit::TestCase

  def test_sig
    der = File.binread('sig.p7s')
    OpenSSL::ASN1.decode(der)
    1.times do
      sig = OpenSSL::ASN1::SignedData.parse(der)
      #cert = OpenSSL::ASN1.decode(der)
      puts der.size
      assert_equal(der, sig.to_der)
    end
  end

end
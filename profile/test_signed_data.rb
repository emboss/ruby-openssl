require 'openssl'
require 'test/unit'
require 'pp'

class TestCert < Test::Unit::TestCase

  def test_sig
    der = File.binread('sig_inf_a.p7s')
    OpenSSL::ASN1.decode(der)
    1.times do
      sig = OpenSSL::ASN1::SignedData.parse(der)
      sig2 = OpenSSL::ASN1::SignedData.parse(sig.to_asn1)
      #cert = OpenSSL::ASN1.decode(der)
      assert_equal(der, sig.to_der)
      assert_equal(der, sig2.to_der)
      pp sig
    end
  end

end
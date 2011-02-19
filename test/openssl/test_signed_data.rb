require_relative 'utils'

if defined?(OpenSSL)

class OpenSSL::TestSignedData < Test::Unit::TestCase

  def test_sign
    data = 'test'
    si = OpenSSL::ASN1::SignerInfo.new
    si.digest_algorithm = OpenSSL::ASN1::AlgorithmIdentifier::SHA1
    si.signature_algorithm = OpenSSL::ASN1::AlgorithmIdentifier::RSA
    dn = OpenSSL::ASN1::DistinguishedName.create('/C=DE/O=Ruby/CN=Ruby CA')
    si.set_issuer_serial(dn, 1)
    si.sign(OpenSSL::TestUtils::TEST_KEY_RSA2048, data)
    pp si
  end

end

end

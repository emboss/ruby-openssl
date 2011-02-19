require_relative 'utils'

if defined?(OpenSSL)

class OpenSSL::TestNames < Test::Unit::TestCase

  def test_dn
    ary = [
        ['C', 'DE'],
        ['O', 'Ruby'],
        ['OU', 'Ruby OpenSSL'],
        ['CN', 'Common Name']
    ]
    dn = OpenSSL::ASN1::DistinguishedName.create(ary)
    asn1 = dn.to_asn1
    #TODO check asn1 structure
  end

  def test_dn_parse
    ary = [
        ['C', 'DE'],
        ['O', 'Ruby'],
        ['OU', 'Ruby OpenSSL'],
        ['CN', 'Common Name']
    ]
    str = '/C=DE/O=Ruby/OU=Ruby OpenSSL/CN=Common Name'

    dn1 = OpenSSL::ASN1::DistinguishedName.create(ary)
    dn2 = OpenSSL::ASN1::DistinguishedName.create(str)
    assert_equal(dn1.to_der, dn2.to_der)
  end

end

end
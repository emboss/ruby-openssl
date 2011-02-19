require 'openssl'
require 'test/unit'
require 'pp'

class TimestampTest < Test::Unit::TestCase

  def test_ts
    der = File.binread('sig_inf_a.p7s')
    OpenSSL::ASN1.decode(der)
    sig = OpenSSL::ASN1::SignedData.parse(der)
    si = sig.content.signer_infos.first
    signature_ts_attr = si.unsigned_attributes.select { |attr| attr.type == 'id-smime-aa-timeStampToken' }.first
    ts = OpenSSL::ASN1::SignedData.parse(signature_ts_attr.value.first.to_asn1)
    tst = OpenSSL::ASN1::TSTInfo.parse(ts.content.encap_content_info.content)
    pp tst
  end
end
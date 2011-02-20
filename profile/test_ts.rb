require 'openssl'
require 'test/unit'
require 'pp'

#class TimestampTest < Test::Unit::TestCase

#  def test_ts
    der = File.binread('sig_inf_a.p7s')
    OpenSSL::ASN1.decode(der)
    sig = OpenSSL::ASN1::SignedData.parse(der)
    si = sig.signers.first
    signature_ts_attr = si.unsigned_attr('id-smime-aa-timeStampToken')
    ts = OpenSSL::ASN1::SignedData.parse(signature_ts_attr.value.first.value)
    tst = OpenSSL::ASN1::TSTInfo.parse(ts.data)
    #pp sig.certs
    certs = sig.certs
    pkc = OpenSSL::X509::Certificate.new(certs.first.to_der)
    pkey = pkc.public_key
    sig.signers.first.verify(pkey, sig.data)
#  end
#end
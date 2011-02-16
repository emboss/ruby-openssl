
module OpenSSL::ASN1
  class Extension
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_object_id :id
      asn1_boolean :critical, { default: false }
      asn1_octet_string :value
    end
  end

  class Time
      include OpenSSL::ASN1::Template

      asn1_declare :CHOICE do
        asn1_utc_time
        asn1_generalized_time
      end
  end

  class Validity
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_template OpenSSL::ASN1::Time, :not_before
        asn1_template OpenSSL::ASN1::Time, :not_after
      end
  end

end
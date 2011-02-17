
module OpenSSL::ASN1

  class DistinguishedName
    include OpenSSL::ASN1::Template

    class DirectoryString
      include OpenSSL::ASN1::Template

      asn1_declare :CHOICE do
        asn1_t61_string
        asn1_ia5_string
        asn1_printable_string
        asn1_universal_string
        asn1_utf8_string
        asn1_bmp_string
      end
    end

    class AttributeTypeAndValue
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_object_id :type
        asn1_template DirectoryString, :value
      end
    end

    class RelativeDistinguishedName
      include OpenSSL::ASN1::Template

      asn1_declare :SET_OF, AttributeTypeAndValue
    end

    asn1_declare :SEQUENCE_OF, RelativeDistinguishedName
  end

  class AlgorithmIdentifier
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_object_id :algorithm
      asn1_template Any, :parameters, { optional: true }
    end
  end

end


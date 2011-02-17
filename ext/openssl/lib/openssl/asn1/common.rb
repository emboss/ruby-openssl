
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

  class GeneralName
    include OpenSSL::ASN1::Template

    class OtherName
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_object_id :type_id
        asn1_template OpenSSL::ASN1::Any, :value, { tag: 0, tagging: :EXPLICIT }
      end
    end

    class EDIPartyName
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_template DistinguishedName::DirectoryString, :name_assigner, { tag: 0, tagging: :IMPLICIT, optional: true }
        asn1_template DistinguishedName::DirectoryString, :party_name, { tag: 1, tagging: :IMPLICIT }
      end
    end

    asn1_declare :CHOICE do
      asn1_template OtherName, nil, { tag: 0, tagging: :IMPLICIT }
      asn1_ia5_string nil, { tag: 1, tagging: :IMPLICIT }
      asn1_ia5_string nil, { tag: 2, tagging: :IMPLICIT }
      asn1_template OpenSSL::ASN1::Any, nil, { tag: 3, tagging: :IMPLICIT }
      asn1_template DistinguishedName, nil, { tag: 4, tagging: :EXPLICIT }
      asn1_template EDIPartyName, nil, { tag: 5, tagging: :IMPLICIT }
      asn1_ia5_string nil, { tag: 6, tagging: :IMPLICIT }
      asn1_octet_string nil, { tag: 7, tagging: :IMPLICIT }
      asn1_object_id nil, { tag: 8, tagging: :IMPLICIT }
    end
  end

  class AlgorithmIdentifier
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_object_id :algorithm
      asn1_template Any, :parameters, { optional: true }
    end
  end

end


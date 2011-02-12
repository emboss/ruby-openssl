
module OpenSSL

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
      asn1_template Time, :not_before
      asn1_template Time, :not_after
    end
  end

  class Extension
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_object_id :id
      asn1_boolean :critical, { default: false }
      asn1_octet_string :value
    end
  end

  class AlgorithmIdentifier
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_object_id :algorithm
      asn1_any :parameters, { optional: true }
    end
  end

  class SubjectPublicKeyInfo
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_template AlgorithmIdentifier, :algorithm
      asn1_bit_string :subject_public_key
    end
  end

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

  class DistinguishedName
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE_OF, RelativeDistinguishedName
  end

  class TBSCertificate
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_integer :version, { tag: 0, tagging: :EXPLICIT, default: 0 }
      asn1_integer :serial_number
      asn1_template AlgorithmIdentifier, :signature_algorithm
      asn1_template DistinguishedName, :issuer
      asn1_template Validity, :validity
      asn1_template DistinguishedName, :subject
      asn1_template SubjectPublicKeyInfo, :subject_public_key_info
      asn1_bit_string :issuer_unique_id, { tag: 1, tagging: :IMPLICIT, optional: true }
      asn1_bit_string :subject_unique_id, { tag: 2, tagging: :IMPLICIT, optional: true }
      asn1_sequence_of Extension, :extensions, { tag: 3, tagging: :EXPLICIT, optional: true }
    end
  end

  class Certificate
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_template TBSCertificate, :tbs_certificate
      asn1_template AlgorithmIdentifier, :signature_algorithm
      asn1_bit_string :signature_value
    end
  end

end

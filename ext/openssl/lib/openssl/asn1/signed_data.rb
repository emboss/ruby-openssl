require_relative 'common'
require_relative 'certificate'
require_relative 'crl'

module OpenSSL::ASN1

  class CertificateChoice
    include OpenSSL::ASN1::Template

    asn1_declare :CHOICE do
      asn1_template OpenSSL::ASN1::Certificate
      asn1_any #TODO
    end
  end

  class OtherRevocationInfoFormat
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_object_id :info_format
      asn1_any :revocation_info
    end
  end

  class RevocationInfoChoice
    include OpenSSL::ASN1::Template

    asn1_declare :CHOICE do
      asn1_template OpenSSL::ASN1::Crl
      asn1_template OtherRevocationInfoFormat, nil, { tag: 1, tagging: :IMPLICIT }
    end
  end

  class EncapsulatedContentInfo
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_object_id :content_type
      asn1_octet_string :content, { tag: 0, tagging: :EXPLICIT, optional: true }
    end
  end

  class IssuerSerialNumber
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_template OpenSSL::ASN1::DistinguishedName, :issuer
      asn1_integer :serial_number
    end
  end

  class Attribute
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_object_id :type
      asn1_any :value #SET OF ANY
    end
  end

  class SignerInfo
    include OpenSSL::ASN1::Template

    class SignerIdentifier
      include OpenSSL::ASN1::Template

      asn1_declare :CHOICE do
        asn1_template IssuerSerialNumber
        asn1_octet_string nil, { tag: 0, tagging: :IMPLICIT } #TODO implicit or explicit
      end
    end

    asn1_declare :SEQUENCE do
      asn1_integer :version
      asn1_template SignerIdentifier, :signer_identifier
      asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :digest_algorithm
      asn1_set_of Attribute, :signed_attributes, { tag: 0, tagging: :IMPLICIT, optional: true }
      asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :signature_algorithm
      asn1_octet_string :signature
      asn1_set_of Attribute, :unsigned_attributes, { tag: 1, tagging: :IMPLICIT, optional: true }
    end
  end

  class SignedData
    include OpenSSL::ASN1::Template


    class Content # the actual SignedData
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_integer :version
        asn1_set_of OpenSSL::ASN1::AlgorithmIdentifier, :digest_algorithms
        asn1_template EncapsulatedContentInfo, :encap_content_info
        asn1_set_of CertificateChoice, :certificates, { tag: 0, tagging: :IMPLICIT, optional: true }
        asn1_set_of RevocationInfoChoice, :crls, { tag: 1, tagging: :IMPLICIT, optional: true }
        asn1_set_of SignerInfo, :signer_infos
      end
    end

    asn1_declare :SEQUENCE do
      asn1_object_id :content_type
      asn1_template Content, :content, { tag: 0, tagging: :EXPLICIT }
    end
  end
end

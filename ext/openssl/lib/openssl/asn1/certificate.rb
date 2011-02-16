require_relative 'common'
require_relative 'x509_common'

module OpenSSL::ASN1

  class Certificate
    include OpenSSL::ASN1::Template

    class SubjectPublicKeyInfo
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :algorithm
        asn1_bit_string :subject_public_key
      end
    end

    class TBSCertificate
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_integer :version, { tag: 0, tagging: :EXPLICIT, default: 0 }
        asn1_integer :serial_number
        asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :signature_algorithm
        asn1_template OpenSSL::ASN1::DistinguishedName, :issuer
        asn1_template OpenSSL::ASN1::Validity, :validity
        asn1_template OpenSSL::ASN1::DistinguishedName, :subject
        asn1_template SubjectPublicKeyInfo, :subject_public_key_info
        asn1_bit_string :issuer_unique_id, { tag: 1, tagging: :IMPLICIT, optional: true }
        asn1_bit_string :subject_unique_id, { tag: 2, tagging: :IMPLICIT, optional: true }
        asn1_sequence_of OpenSSL::ASN1::Extension, :extensions, { tag: 3, tagging: :EXPLICIT, optional: true }
      end
    end

    asn1_declare :SEQUENCE do
      asn1_template TBSCertificate, :tbs_certificate
      asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :signature_algorithm
      asn1_bit_string :signature_value
    end
  end

end

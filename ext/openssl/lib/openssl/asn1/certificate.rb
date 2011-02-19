require_relative 'common'
require_relative 'x509_common'

module OpenSSL::ASN1

  class Certificate
    include OpenSSL::ASN1::Template

    class SubjectPublicKeyInfo
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :algorithm
        asn1_bit_string :subject_pkey
      end
    end

    class TBSCertificate
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_integer :version, { tag: 0, tagging: :EXPLICIT, default: 0 }
        asn1_integer :serial
        asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :algorithm
        asn1_template OpenSSL::ASN1::DistinguishedName, :issuer
        asn1_template OpenSSL::ASN1::Validity, :validity
        asn1_template OpenSSL::ASN1::DistinguishedName, :subject
        asn1_template SubjectPublicKeyInfo, :subject_pkey
        asn1_bit_string :issuer_id, { tag: 1, tagging: :IMPLICIT, optional: true }
        asn1_bit_string :subject_id, { tag: 2, tagging: :IMPLICIT, optional: true }
        asn1_sequence_of OpenSSL::ASN1::Extension, :extensions, { tag: 3, tagging: :EXPLICIT, optional: true }
      end
    end

    asn1_declare :SEQUENCE do
      asn1_template TBSCertificate, :tbs_cert
      asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :algorithm
      asn1_bit_string :signature
    end

    def serial; tbs_cert.serial; end
    def serial=(serial); tbs_cert.serial=serial; end
    def issuer; tbs_cert.issuer; end
    def validity; tbs_cert.validity; end
    def validity=(validity); tbs_cert.validity=validity; end
    def subject; tbs_cert.subject; end
    def subject_pkey; tbs_cert.subject_pkey; end
    def subject_pkey=(spk); tbs_cert.subject_pkey=spk; end
    def issuer_id; tbs_cert.issuer_id; end
    def issuer_id=(id); tbs_cert.issuer_id=id; end
    def subject_id; tbs_cert.subject_id; end
    def subject_id=(id); tbs_cert.subject_id=id; end
    def extensions; tbs_cert.extensions; end
    def extensions=(exts); tbs_cert.extensions=exts; end

  end
end

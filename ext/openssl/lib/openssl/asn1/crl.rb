require_relative 'common'

module OpenSSL::ASN1
  class Crl
    include OpenSSL::ASN1::Template

    class RevokedCertificates
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_integer :serial_number
        asn1_template OpenSSL::ASN1::Time, :revocation_date
        asn1_template OpenSSL::ASN1::Extension, :crl_entry_extensions
      end
    end

    class TBSCertList
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_integer :version, { optional: true, default: 1 }
        asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :signature_algorithm
        asn1_template OpenSSL::ASN1::DistinguishedName, :issuer
        asn1_template OpenSSL::ASN1::Time, :this_update
        asn1_template OpenSSL::ASN1::Time, :next_update
        asn1_sequence_of RevokedCertificates, :revoked_certificates, { optional: true }
        asn1_template OpenSSL::ASN1::Extension, :extensions, { tag: 0, tagging: :EXPLICIT, optional: true }
      end
    end

    asn1_declare :SEQUENCE do
      asn1_template TBSCertList, :tbs_cert_list
      asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :signature_algorithm
      asn1_bit_string :signature
    end
  end
end

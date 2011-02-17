require_relative 'common'
require_relative 'signed_data'

module OpenSSL::ASN1

  class MessageImprint
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :algorithm
      asn1_octet_string :hash
    end
  end

  class TimestampRequest
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_integer :version, { default: 1 }
      asn1_template MessageImprint, :message_imprint
      asn1_object_id :policy, { optional: true }
      asn1_integer :nonce, { optional: true }
      asn1_boolean :cert_requested, { default: false }
      asn1_sequence_of OpenSSL::ASN1::Extension, :extensions, { tag: 0, tagging: :IMPLICIT, optional: true }
    end

    def initialize(optional=nil, parse=false)
      super
      @cert_requested = true unless parse #intentional default for creation
    end
  end


  class TimestampResponse
    include OpenSSL::ASN1::Template

    class PKIStatusInfo
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_integer :status
        asn1_sequence_of OpenSSL::ASN1::UTF8String, :text, { optional: true }
        asn1_bit_string :failure_info, { optional: true }
      end
    end

    asn1_declare :SEQUENCE do
      asn1_template PKIStatusInfo, :status
      asn1_template OpenSSL::ASN1::SignedData, :token, { optional: true }
    end
  end

  class TSTInfo
    include OpenSSL::ASN1::Template

    class Accuracy
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_integer :seconds, { optional: true }
        asn1_integer :millis, { tag: 0, tagging: :IMPLICIT, optional: true }
        asn1_integer :micros, { tag: 1, tagging: :IMPLICIT, optional: true }
      end
    end

    asn1_declare :SEQUENCE do
      asn1_integer :version, { default: 1 }
      asn1_object_id :policy
      asn1_template MessageImprint, :message_imprint
      asn1_integer :serial_number
      asn1_generalized_time :time
      asn1_template Accuracy, :accuracy, { optional: true }
      asn1_boolean :ordering, { default: false }
      asn1_integer :nonce, { optional: true }
      asn1_template OpenSSL::ASN1::GeneralName, :tsa, { tag: 0, tagging: :EXPLICIT, optional: true }
      asn1_sequence_of OpenSSL::ASN1::Extension, :extensions, { tag: 1, tagging: :IMPLICIT, optional: true }
    end
  end

end

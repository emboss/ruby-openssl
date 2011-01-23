module OpenSSL
  module Timestamp
    
    class Extension
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_object_id :id
        asn1_boolean :critical, { default: false }
        asn1_octet_string :value
      end
    end
    
    class Request
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :version, { default: 1 }
        asn1_sequence do
          asn1_sequence do
            asn1_object_id :algorithm
            asn1_any :parameters, { optional: true, parse_ignore: true }
          end
          asn1_octet_string :message_imprint
        end
        asn1_object_id :policy_id, { optional: true }
        asn1_integer :nonce, { optional: true }
        asn1_boolean :cert_requested, { default: false }
        asn1_sequence_of Extension, :extensions, { tag: 0, 
                                                   tagging: :IMPLICIT, 
                                                   optional: true }
      end
    end
  end
end






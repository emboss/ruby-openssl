
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

    def self.create(name=nil, utf8=false)
      dn = DistinguishedName.new
      unless name.respond_to?(:each)
        ary = name.scan(/\s*([^\/,]+)\s*/).collect{|i| i[0].split("=", 2) }
      else
        ary = name
      end
      dn.value = ary.map do |pair|
         atv = AttributeTypeAndValue.new
         atv.type = OpenSSL::ASN1::ObjectId.new(pair.first)
         atv.value = DirectoryString.new
         type = utf8 ? OpenSSL::ASN1::UTF8String : OpenSSL::ASN1::PrintableString
         atv.value.value = OpenSSL::ASN1::Template::ChoiceValue.new(type, pair.last)
         rdn = RelativeDistinguishedName.new
         rdn.value = [atv]
         rdn
      end
      dn
    end
  end

  class GeneralName
    include OpenSSL::ASN1::Template

    class OtherName
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_object_id :type
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
      asn1_template OpenSSL::ASN1::Any, :params, { optional: true }
    end

    def self.null_params
      OpenSSL::ASN1::Any.new(OpenSSL::ASN1::Null.new(nil))
    end

    def self.algorithm_null_params(name)
      alg = AlgorithmIdentifier.new
      alg.algorithm = OpenSSL::ASN1::ObjectId.new(name)
      alg.params = null_params
      alg
    end

    SHA1 = algorithm_null_params('SHA1')
    SHA256 = algorithm_null_params('SHA256')
    SHA512 = algorithm_null_params('SHA512')
    RSA = algorithm_null_params('rsaEncryption')
  end

end


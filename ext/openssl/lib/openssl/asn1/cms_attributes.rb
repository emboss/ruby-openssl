
module OpenSSL::ASN1::Attributes

  class ContentType

    ID = '1.2.840.113549.1.9.3'
    ID_ASN1 = OpenSSL::ASN1::ObjectId.new(ID)

    attr_accessor :type

    def initialize(type)
      @type = type
    end

    def self.from_attr(attr)
      unless OpenSSL::ASN1::ObjectId.new(attr.type).to_der == ID_ASN1.to_der ||
             attr.value.size == 1 ||
             attr.value.first.value.tag == OpenSSL::ASN1::OBJECT_ID
        raise OpenSSL::ASN1::ASN1Error.new("Attribute is not a ContentType")
      end
      ContentType.new(attr.value.first.value.value)
    end

    def to_attr
      attr = OpenSSL::ASN1::Attribute.new
      attr.type = ID
      attr.value = [OpenSSL::ASN1::Any.new(OpenSSL::ASN1::ObjectId.new(@type))]
      attr
    end
  end

  class MessageDigest

    ID = '1.2.840.113549.1.9.4'
    ID_ASN1 = OpenSSL::ASN1::ObjectId.new(ID)

    attr_accessor :value

    def initialize(value)
      @value = value
    end

    def self.from_attr(attr)
      unless OpenSSL::ASN1::ObjectId.new(attr.type).to_der == ID_ASN1.to_der ||
             attr.value.size == 1 ||
             attr.value.first.value.tag == OpenSSL::ASN1::OCTET_STRING
        raise OpenSSL::ASN1::ASN1Error.new("Attribute is not a MessageDigest")
      end
      MessageDigest.new(attr.value.first.value.value)
    end

    def to_attr
      attr = OpenSSL::ASN1::Attribute.new
      attr.type = ID
      attr.value = [OpenSSL::ASN1::Any.new(OpenSSL::ASN1::OctetString.new(@value))]
      attr
    end

  end

end
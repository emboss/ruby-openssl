require_relative 'common'
require_relative 'certificate'
require_relative 'crl'
require_relative 'cms_attributes'

module OpenSSL::ASN1

  class CertificateChoice
    include OpenSSL::ASN1::Template

    asn1_declare :CHOICE do
      asn1_template OpenSSL::ASN1::Certificate
      asn1_template OpenSSL::ASN1::Any #TODO
    end
  end

  class OtherRevocationInfoFormat
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_object_id :format
      asn1_template OpenSSL::ASN1::Any, :rev_info
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
      asn1_object_id :type
      asn1_octet_string :content, { tag: 0, tagging: :EXPLICIT, optional: true }
    end
  end

  class IssuerSerialNumber
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_template OpenSSL::ASN1::DistinguishedName, :issuer
      asn1_integer :serial
    end
  end

  class Attribute
    include OpenSSL::ASN1::Template

    asn1_declare :SEQUENCE do
      asn1_object_id :type
      asn1_set_of OpenSSL::ASN1::Any, :value
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
      asn1_template SignerIdentifier, :signer_id
      asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :digest_algorithm
      asn1_set_of Attribute, :signed_attrs, { tag: 0, tagging: :IMPLICIT, optional: true }
      asn1_template OpenSSL::ASN1::AlgorithmIdentifier, :signature_algorithm
      asn1_octet_string :signature
      asn1_set_of Attribute, :unsigned_attrs, { tag: 1, tagging: :IMPLICIT, optional: true }
    end

    def signed_attr(id)
      attrs_single(:@signed_attrs, id)
    end

    def unsigned_attr(id)
      attrs_single(:@unsigned_attrs, id)
    end

    def set_issuer_serial(issuer, serial)
      iss = IssuerSerialNumber.new
      iss.serial = serial
      if issuer.is_a?(String) || issuer.respond_to?(:each)
        name = OpenSSL::DistinguishedName.new(issuer)
      else
        name = issuer
      end
      iss.issuer = name
      templ = SignerIdentifier.new
      templ.value = OpenSSL::ASN1::Template::ChoiceValue.new(OpenSSL::ASN1::IssuerSerialNumber, iss)
      @signer_id = templ
    end

    def sign(pkey, data, content_type=nil)
      unless @version
        @version = @signer_id.value.type == OpenSSL::ASN1::IssuerSerialNumber ? 1 : 3
      end
      content_type ||= SignedData::ID_DATA
      add_mandatory_attributes(data, content_type)
      der = OpenSSL::ASN1::Set.new(to_asn1_iv(:signed_attrs).value).to_der #universal encoding is used
      md = OpenSSL::Digest.new(digest_algorithm.algorithm.sn)
      @signature = pkey.sign(md, der)
    end

    def verify(pkey, data, content_type=nil)
      check_version
      content_type ||= SignedData::ID_DATA
      @signed_attrs.empty? ?
        verify_no_attrs(pkey, data) :
        verify_attrs(pkey, data, content_type)
    end

    private

    def attrs_single(accessor, id)
      ary = attrs(accessor, id)
      unless ary.size == 1
        raise OpenSSL::ASN1::ASN1Error.new("There are multiple values of attribute #{id.sn}")
      end
      ary.first
    end

    def attrs(accessor, id)
      unless id.respond_to?(:to_der)
        asn1id = OpenSSL::ASN1::ObjectId.new(id)
      else
        asn1id = id
      end
      ary = instance_variable_get(accessor).select do |attr|
        attr.type.oid == asn1id.oid
      end
      ary.empty? ? nil : ary
    end

    def add_mandatory_attributes(data, content_type)
      @signed_attrs ||= Array.new
      @signed_attrs << OpenSSL::ASN1::Attributes::ContentType.new(content_type).to_attr
      md = OpenSSL::Digest.new(@digest_algorithm.algorithm.sn)
      @signed_attrs << OpenSSL::ASN1::Attributes::MessageDigest.new(md.digest(data)).to_attr
    end

    def check_version
      if @signer_id.value.type == OpenSSL::ASN1::IssuerSerialNumber
        unless @version == 1
          raise OpenSSL::ASN1::ASN1Error.new("Version is not 1 although signer identifier mandates it.")
        end
      else
        unless @version == 3
          raise OpenSSL::ASN1::ASN1Error.new("Version is not 3 although signer identifier mandates it.")
        end
      end
    end

    def verify_no_attrs(pkey, data)
      unless pkey.verify(OpenSSL::Digest.new(@digest_algorithm.algorithm.sn), @signature, data)
        raise OpenSSL::ASN1::ASN1Error.new('Siganture is invalid.')
      end
    end

    def verify_attrs(pkey, data, content_type)
      ct_attr = OpenSSL::ASN1::Attributes::ContentType.from_attr(
          signed_attr(OpenSSL::ASN1::Attributes::ContentType::ID))

      unless content_type.oid == ct_attr.type.oid
        raise OpenSSL::ASN1::ASN1Error.new('ContentType attribute differs from actual content type')
      end

      der = OpenSSL::ASN1::Set.new(to_asn1_iv(:signed_attrs).value).to_der #universal encoding is used
      unless pkey.verify(OpenSSL::Digest.new(@digest_algorithm.algorithm.sn), @signature, der)
        raise OpenSSL::ASN1::ASN1Error.new('Signature value is invalid')
      end

      md_attr = OpenSSL::ASN1::Attributes::MessageDigest.from_attr(
          signed_attr(OpenSSL::ASN1::Attributes::MessageDigest::ID))

      unless OpenSSL::Digest.new(@digest_algorithm.algorithm.sn).digest(data) == md_attr.value
        raise OpenSSL::ASN1::ASN1Error.new('MessageDigest attribute value is invalid')
      end
    end
  end

  class SignedData
    include OpenSSL::ASN1::Template

    ID_DATA = OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.7.1')

    class Content # the actual SignedData
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_integer :version
        asn1_set_of OpenSSL::ASN1::AlgorithmIdentifier, :digest_algorithms
        asn1_template EncapsulatedContentInfo, :data
        asn1_set_of CertificateChoice, :certs, { tag: 0, tagging: :IMPLICIT, optional: true }
        asn1_set_of RevocationInfoChoice, :crls, { tag: 1, tagging: :IMPLICIT, optional: true }
        asn1_set_of SignerInfo, :signers
      end
    end

    asn1_declare :SEQUENCE do
      asn1_object_id :type
      asn1_template Content, :content, { tag: 0, tagging: :EXPLICIT }
    end

    def data; content.data.content; end
    def data=(data); content.data.content=data; end
    def digest_algorithms; content.digest_algorithms; end
    def digest_algorithms=(algos); content.digest_algorithms=algos; end
    def signers; content.signers; end
    def detached?; data == nil; end

    def certs
      ret = content.certs.map do |choice|
        choice.value.value if choice.value.type == OpenSSL::ASN1::Certificate
      end
      ret.empty? ? nil : ret
    end

    def add_cert(cert)
      content.certs ||= Array.new
      if cert.is_a?(OpenSSL::ASN1::Template::ChoiceValue)
        content.certs << cert
      else
        content.certs << OpenSSL::ASN1::Template::ChoiceValue.new(OpenSSL::ASN1::Certificate, cert)
      end
    end

    def certs=(certs)
      content.certs = Array.new
      certs.each do |cert|
        add_cert(cert)
      end
    end

    def crls
      ret = content.crls.map do |choice|
        choice.value.value if choice.value.type == OpenSSL::ASN1::Crl
      end
      ret.empty? ? nil : ret
    end

    def add_crl(crl)
      content.crls ||= Array.new
      if crl.is_a?(OpenSSL::ASN1::Template::ChoiceValue)
        content.crls << crl
      else
        content << OpenSSL::ASN1::Template::ChoiceValue.new(OpenSSL::ASN1::Crl, crl)
      end
    end

    def crls=(crls)
      content.crls = Array.new
      crls.each do |crl|
        add_crl(crl)
      end
    end

  end
end

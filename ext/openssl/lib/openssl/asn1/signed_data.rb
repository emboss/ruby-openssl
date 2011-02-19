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
      @version = signer_id.value.type == OpenSSL::ASN1::IssuerSerialNumber ? 1 : 3
      content_type ||= SignedData::ID_DATA
      add_mandatory_attributes(data, content_type)
      asn1 = OpenSSL::ASN1::Set.new(to_asn1_iv(:signed_attrs).value) #universal encoding is used
      md = OpenSSL::Digest.new(digest_algorithm.algorithm)
      @signature = pkey.sign(md, asn1.to_der)
    end

    private

    def add_mandatory_attributes(data, content_type)
      @signed_attrs ||= Array.new
      @signed_attrs << OpenSSL::ASN1::Attributes::ContentType.new(content_type).to_attribute
      md = OpenSSL::Digest.new(digest_algorithm.algorithm)
      @signed_attrs << OpenSSL::ASN1::Attributes::MessageDigest.new(md.digest(data)).to_attribute
    end

  end

  class SignedData
    include OpenSSL::ASN1::Template

    ID_DATA = '1.2.840.113549.1.7.1'

    class Content # the actual SignedData
      include OpenSSL::ASN1::Template

      asn1_declare :SEQUENCE do
        asn1_integer :version
        asn1_set_of OpenSSL::ASN1::AlgorithmIdentifier, :digest_algorithms
        asn1_template EncapsulatedContentInfo, :data
        asn1_set_of CertificateChoice, :certificates, { tag: 0, tagging: :IMPLICIT, optional: true }
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

    def certificates
      ret = content.certificates.map do |choice|
        choice.value.value if choice.value.type == OpenSSL::ASN1::Certificate
      end
      ret.empty? ? nil : ret
    end

    def add_certificate(cert)
      content.certificates ||= Array.new
      if cert.is_a?(OpenSSL::ASN1::Template::ChoiceValue)
        content.certificates << cert
      else
        content << OpenSSL::ASN1::Template::ChoiceValue.new(OpenSSL::ASN1::Certificate, cert)
      end
    end

    def certificates=(certs)
      content.certificates = Array.new
      certs.each do |cert|
        add_certificate(cert)
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

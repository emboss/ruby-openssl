require_relative 'utils'

class  OpenSSL::TestASN1 < Test::Unit::TestCase
  def test_asn1_boolean
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_boolean :bool
      end
    end
    
    t = template.new
    t.bool = true
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    asn1bool = asn1.value.first
    assert_universal(OpenSSL::ASN1::BOOLEAN, asn1bool)
    assert_equal(true, asn1bool.value)
    
    p = template.parse(OpenSSL::ASN1.decode(asn1.to_der))
    
    assert_equal(true, p.bool)
  end
  
  #TODO for all primitives
  
  def test_asn1_sequence
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_sequence do
          asn1_integer :a
        end
      end
    end
    
    t = template.new
    t.a = 1
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    asn1seq = asn1.value.first
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1seq)
    assert_equal(1, asn1.value.size)
    asn1int = asn1seq.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, asn1int)
    assert_equal(1, asn1int.value)
    
    p = template.parse(OpenSSL::ASN1.decode(asn1.to_der))
    
    assert_equal(1, p.a)
  end
  
  def test_asn1_set
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Set do
        asn1_set do
          asn1_integer :a
        end
      end
    end
    
    t = template.new
    t.a = 1
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SET, asn1)
    assert_equal(1, asn1.value.size)
    asn1set = asn1.value.first
    assert_universal(OpenSSL::ASN1::SET, asn1set)
    assert_equal(1, asn1.value.size)
    asn1int = asn1set.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, asn1int)
    assert_equal(1, asn1int.value)
    
    p = template.parse(OpenSSL::ASN1.decode(asn1.to_der))
    
    assert_equal(1, p.a)
  end
  
  def assert_universal(tag, asn1)
    assert_equal(tag, asn1.tag)
    assert_equal(false, asn1.infinite_length)
    assert_nil(asn1.tagging)
    assert_equal(:UNIVERSAL, asn1.tag_class)
  end
end



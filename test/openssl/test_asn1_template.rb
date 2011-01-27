require_relative 'utils'

class  OpenSSL::TestASN1 < Test::Unit::TestCase
  def test_asn1_boolean
    check_asn1_primitive(:asn1_boolean, OpenSSL::ASN1::BOOLEAN, true)
  end
  
  def test_asn1_integer
    check_asn1_primitive(:asn1_integer, OpenSSL::ASN1::INTEGER, 1)
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
    
    der = asn1.to_der
    p = template.parse(OpenSSL::ASN1.decode(der))
    
    assert_equal(1, p.a)
    assert_equal(der, p.to_der)
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
    
    der = asn1.to_der
    p = template.parse(OpenSSL::ASN1.decode(der))
    
    assert_equal(1, p.a)
    assert_equal(der, p.to_der)
  end
  
  def test_asn1_sequence_of_primitive
    check_asn1_constructive_of_primitive(:asn1_sequence_of, OpenSSL::ASN1::SEQUENCE)
  end
  
  def test_asn1_set_of_primitive
    check_asn1_constructive_of_primitive(:asn1_set_of, OpenSSL::ASN1::SET)
  end
  
  def test_asn1_any
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_any :a
      end
    end
    
    t = template.new
    t.a = OpenSSL::ASN1::Integer.new(1)
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    asn1int = asn1.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, asn1int)
    assert_equal(1, asn1int.value)
    
    der = asn1.to_der
    p = template.parse(OpenSSL::ASN1.decode(der))
    
    assert_equal(true, p.a.is_a?(OpenSSL::ASN1::Integer))
    assert_universal(OpenSSL::ASN1::INTEGER, p.a)
    assert_equal(1, p.a.value)
    assert_equal(der, p.to_der)
  end
  
  def test_asn1_any_tagged
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_any :a, { tag: 0, tagging: :IMPLICIT}
      end
    end
    
    t = template.new
    t.a = OpenSSL::ASN1::Integer.new(1)
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    asn1int = asn1.value.first
    assert_tagged(0, :IMPLICIT, asn1int)
    assert_equal(1, asn1int.value)
    
    der = asn1.to_der
    p = template.parse(OpenSSL::ASN1.decode(der))
    
    assert_equal(true, p.a.is_a?(OpenSSL::ASN1::ASN1Data))
    assert_tagged(0, nil, p.a)
    
    p.a.tag = OpenSSL::ASN1::INTEGER
    p.a.tag_class = :UNIVERSAL
    pint = OpenSSL::ASN1.decode(p.a.to_der)
    assert_equal(1, pint.value)
    assert_equal(der, p.to_der)
  end
  
  def test_parse_raw
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
        asn1_printable_string :b
        asn1_printable_string :c, { tag: 0, tagging: :IMPLICIT}
        asn1_utc_time :d
      end
    end
    
    vals = []
    vals << OpenSSL::ASN1::Integer.new(1)
    vals << OpenSSL::ASN1::PrintableString.new("a")
    vals << OpenSSL::ASN1::PrintableString.new("b", 0, :IMPLICIT)
    time = Time.at(Time.now.to_i) #suppress usec
    vals << OpenSSL::ASN1::UTCTime.new(time)
    seq = OpenSSL::ASN1::Sequence.new(vals)
    
    #from raw DER
    parsed = template.new(seq.to_der)
    
    assert_equal(1, parsed.a)
    assert_equal("a", parsed.b)
    assert_equal("b", parsed.c)
    assert_equal(time, parsed.d)
    
    #from ASN.1
    p2 = template.new(OpenSSL::ASN1.decode(seq.to_der))
    
    assert_equal(1, p2.a)
    assert_equal("a", p2.b)
    assert_equal("b", p2.c)
    assert_equal(time, p2.d)
    
    #parse from DER
    
    p3 = template.parse(seq.to_der)
    assert_equal(1, p3.a)
    assert_equal("a", p3.b)
    assert_equal("b", p3.c)
    assert_equal(time, p3.d)
  end
  
  def test_optional_at_end_of_sequence
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
        asn1_printable_string :b, { optional: true }
      end
    end
    
    t = template.new
    t.a = 1
    t = template.parse(t.to_der)
    
    assert_equal(1, t.a)
    assert_nil(t.b)
  end
  
  def test_optional_at_start_of_sequence
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a, { optional: true }
        asn1_printable_string :b
      end
    end
    
    t = template.new
    t.b = "b"
    t = template.parse(t.to_der)
    
    assert_nil(t.a)
    assert_equal("b", t.b)
  end
  
  private
  
  def assert_universal(tag, asn1)
    assert_equal(tag, asn1.tag)
    assert_equal(false, asn1.infinite_length)
    assert_nil(asn1.tagging)
    assert_equal(:UNIVERSAL, asn1.tag_class)
  end
  
  def assert_tagged(tag, tagging, asn1)
    assert_equal(tag, asn1.tag)
    assert_equal(false, asn1.infinite_length)
    if asn1.respond_to?(:tagging)
      assert_equal(tagging, asn1.tagging)
    end
    assert_equal(:CONTEXT_SPECIFIC, asn1.tag_class)
  end
  
  def check_asn1_primitive(prim_declare, tag, value)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        send(prim_declare, :name)
      end
    end
    
    t = template.new
    t.name = value
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    asn1prim = asn1.value.first
    assert_universal(tag, asn1prim)
    assert_equal(value, asn1prim.value)
    
    der = asn1.to_der
    p = template.parse(OpenSSL::ASN1.decode(der))
    
    assert_equal(value, p.name)
    assert_equal(der, p.to_der)
  end
  
  def check_asn1_constructive_of_primitive(cons_declare, tag)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        send(cons_declare, OpenSSL::ASN1::Integer, :a)
      end
    end
    
    t = template.new
    t.a = [ 0, 1 ]
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    ary = asn1.value
    assert_universal(tag, ary[0])
    ary = ary[0]
    assert_equal(2, ary.value.size)
    assert_universal(OpenSSL::ASN1::INTEGER, ary.value[0])
    assert_equal(0, ary.value[0].value)
    assert_universal(OpenSSL::ASN1::INTEGER, ary.value[1])
    assert_equal(1, ary.value[1].value)
    
    der = asn1.to_der
    p = template.parse(OpenSSL::ASN1.decode(asn1.to_der))
    
    assert_equal(0, p.a[0])
    assert_equal(1, p.a[1])
    assert_equal(der, p.to_der)
  end
  
end



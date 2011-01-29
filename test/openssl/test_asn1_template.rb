# encoding: UTF-8
require_relative 'utils'

class  OpenSSL::TestASN1 < Test::Unit::TestCase
  def test_asn1_boolean
    check_asn1_primitive(:asn1_boolean, OpenSSL::ASN1::BOOLEAN, true)
  end
  
  def test_asn1_integer
    check_asn1_primitive(:asn1_integer, OpenSSL::ASN1::INTEGER, 1)
  end
  
  def test_asn1_bit_string
    check_asn1_primitive(:asn1_bit_string, OpenSSL::ASN1::BIT_STRING, "\0x01")
  end
  
  def test_asn1_octet_string
    check_asn1_primitive(:asn1_octet_string, OpenSSL::ASN1::OCTET_STRING, "\0x01")
  end
  
  def test_asn1_null
    check_asn1_primitive(:asn1_null, OpenSSL::ASN1::NULL, nil)
  end
  
  def test_asn1_object_id
    check_asn1_primitive(:asn1_object_id, OpenSSL::ASN1::OBJECT, "1.2.3.4.5")
  end
  
  def test_asn1_enumerated
    check_asn1_primitive(:asn1_enumerated, OpenSSL::ASN1::ENUMERATED, 1)
  end
  
  def test_utf8_string_utf8
    check_asn1_primitive(:asn1_utf8_string, OpenSSL::ASN1::UTF8STRING, "äöüß€")
  end
  
  def test_asn1_numeric_string
    check_asn1_primitive(:asn1_numeric_string, OpenSSL::ASN1::NUMERICSTRING, "123")
  end
  
  def test_printable_string
    check_asn1_primitive(:asn1_printable_string, OpenSSL::ASN1::PRINTABLESTRING, "abc")
  end
  
  def test_asn1_t61_string
    check_asn1_primitive(:asn1_t61_string, OpenSSL::ASN1::T61STRING, "abc")
  end
  
  def test_asn1_videotex_string
    check_asn1_primitive(:asn1_videotex_string, OpenSSL::ASN1::VIDEOTEXSTRING, "abc")
  end
  
  def test_ia5_string
    check_asn1_primitive(:asn1_ia5_string, OpenSSL::ASN1::IA5STRING, "abc")
  end
  
  def test_utc_time
    check_asn1_primitive(:asn1_utc_time, OpenSSL::ASN1::UTCTIME, Time.at(Time.now.to_i)) # suppress usec
  end
  
  def test_generalized_time
    check_asn1_primitive(:asn1_generalized_time, OpenSSL::ASN1::GENERALIZEDTIME, Time.at(Time.now.to_i)) # suppress usec
  end
  
  def test_asn1_graphic_string
    check_asn1_primitive(:asn1_graphic_string, OpenSSL::ASN1::GRAPHICSTRING, "abc")
  end
  
  def test_asn1_iso64_string
    check_asn1_primitive(:asn1_iso64_string, OpenSSL::ASN1::ISO64STRING, "abc")
  end
  
  def test_asn1_general_string
    check_asn1_primitive(:asn1_general_string, OpenSSL::ASN1::GENERALSTRING, "abc")
  end
  
  def test_asn1_universal_string
    check_asn1_primitive(:asn1_universal_string, OpenSSL::ASN1::UNIVERSALSTRING, "abc")
  end
  
  def test_asn1_bmp_string
    check_asn1_primitive(:asn1_bmp_string, OpenSSL::ASN1::BMPSTRING, "abc")
  end
  
  def test_asn1_sequence
    check_cons(:asn1_sequence, OpenSSL::ASN1::Sequence)
  end
  
  def test_asn1_set
    check_cons(:asn1_set, OpenSSL::ASN1::Set)
  end
  
  def test_asn1_nested_sequence
    check_cons_nested(:asn1_sequence, OpenSSL::ASN1::SEQUENCE)
  end
  
  def test_asn1_nested_set
    check_cons_nested(:asn1_set, OpenSSL::ASN1::SET)
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
  
  def test_asn1_template
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    container = Class.new do
      include OpenSSL::ASN1::Template
        
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_template template, :a
      end
    end
    
    c = container.new
    c.a.a = 1
    asn1 = c.to_asn1
    
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    seq = asn1.value.first
    assert_universal(OpenSSL::ASN1::SEQUENCE, seq)
    assert_equal(1, seq.value.size)
    int = seq.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    
    der = asn1.to_der
    p = container.parse(der)
    assert_equal(1, p.a.a)
    assert_equal(der, p.to_der)
  end
  
  def test_asn1_choice_int
    check_asn1_choice_int_bool(OpenSSL::ASN1::Integer, 1)
  end
  
  def test_asn1_choice_bool
    check_asn1_choice_int_bool(OpenSSL::ASN1::Boolean, true)
  end
  
  def test_implcitly_tagged_choice_0
    check_implcitly_tagged_choice(0)
  end
  
  def test_implcitly_tagged_choice_1
    check_implcitly_tagged_choice(1)
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
  
  def test_ignore_value_on_parsing
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_null
        asn1_integer :a
      end
    end
    
    t = template.new
    t.a = 1
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(2, asn1.value.size)
    null = asn1.value[0]
    assert_universal(OpenSSL::ASN1::NULL, null)
    assert_nil(null.value)
    asn1int = asn1.value[1]
    assert_universal(OpenSSL::ASN1::INTEGER, asn1int)
    assert_equal(1, asn1int.value)
    
    der = asn1.to_der
    p = template.parse(der)
    assert_equal(1, t.a)
    assert_equal(der, p.to_der)
  end
  
  def test_asn1_template_mandatory_initialized
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    container = Class.new do
      include OpenSSL::ASN1::Template
        
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_template template, :a
      end
    end
    
    c = container.new
    assert_nil(c.a.a)
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
  
  def check_cons(cons_declare, type)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      proc = proc { asn1_integer :a }
      
      asn1_declare type do
        send(cons_declare, &proc)
      end
    end
    
    t = template.new
    t.a = 1
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::CLASS_TAG_MAP[type], asn1)
    assert_equal(1, asn1.value.size)
    asn1set = asn1.value.first
    assert_universal(OpenSSL::ASN1::CLASS_TAG_MAP[type], asn1set)
    assert_equal(1, asn1.value.size)
    asn1int = asn1set.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, asn1int)
    assert_equal(1, asn1int.value)
    
    der = asn1.to_der
    p = template.parse(OpenSSL::ASN1.decode(der))
    
    assert_equal(1, p.a)
    assert_equal(der, p.to_der)
  end
  
  def check_cons_nested(cons_declare, tag)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      inner = Proc.new do
        asn1_boolean :b  
      end
      
      outer = Proc.new do
        asn1_integer :a
        send(cons_declare, &inner)
      end
      
      asn1_declare OpenSSL::ASN1::Sequence do
        send(cons_declare, &outer)
      end
    end
    
    t = template.new
    t.a = 1
    t.b = true
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    asn1seq = asn1.value.first
    assert_universal(tag, asn1seq)
    assert_equal(2, asn1seq.value.size)
    asn1int = asn1seq.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, asn1int)
    assert_equal(1, asn1int.value)
    innerseq = asn1seq.value[1]
    assert_universal(tag, innerseq)
    assert_equal(1, innerseq.value.size)
    bool = innerseq.value.first
    assert_universal(OpenSSL::ASN1::BOOLEAN, bool)
    assert_equal(true, bool.value)
    
    der = asn1.to_der
    p = template.parse(OpenSSL::ASN1.decode(der))
    
    assert_equal(1, p.a)
    assert_equal(true, p.b)
    assert_equal(der, p.to_der)
  end
  
  def check_asn1_choice_int_bool(type, value)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_choice :a do
          asn1_integer
          asn1_boolean
        end
      end
    end
    
    t = template.new
    t.a = OpenSSL::ASN1::Template::ChoiceValue.new(type, value)
    
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    int = asn1.value.first
    assert_universal(OpenSSL::ASN1::CLASS_TAG_MAP[type], int)
    assert_equal(value, int.value)
    
    der = asn1.to_der
    p = template.parse(der)
    cv = p.a
    assert_equal(type, cv.type)
    assert_equal(value, cv.value)
    assert_nil(cv.tag)
    assert_equal(der, p.to_der)
  end
  
  def check_implcitly_tagged_choice(tag)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_choice :a do
          asn1_integer nil, { tag: 0, tagging: :IMPLICIT }
          asn1_integer nil, { tag: 1, tagging: :IMPLICIT }
        end
      end
    end
    
    t = template.new
    t.a = OpenSSL::ASN1::Template::ChoiceValue.new(OpenSSL::ASN1::Integer, 1, tag)
    
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    int = asn1.value.first
    assert_tagged(tag, :IMPLICIT, int)
    assert_equal(1, int.value)
    der = asn1.to_der
    
    p = template.parse(der)
    cv = p.a
    assert_equal(OpenSSL::ASN1::Integer, cv.type)
    assert_equal(1, cv.value)
    assert_equal(tag, cv.tag)
    assert_equal(der, p.to_der)
  end
  
end


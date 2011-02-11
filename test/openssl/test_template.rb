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
  
  def test_implicit_tagged_primitive
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_printable_string :a, { tag: 0, tagging: :IMPLICIT }
      end
    end
    
    t = template.new
    t.a = 'a'
    asn1 = t.to_asn1
    
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    s = asn1.value.first
    assert_tagged(0, :IMPLICIT, s)
    assert_equal('a', s.value)
    
    der = asn1.to_der
    p = template.parse(der)
    
    assert_equal('a', p.a)
    assert_equal(der, p.to_der)
  end
  
  def test_explicit_tagged_primitive
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a, { tag: 0, tagging: :EXPLICIT }
      end
    end
    
    t = template.new
    t.a = 1
    asn1 = t.to_asn1
    
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    asn1data = asn1.value.first
    assert_tagged(0, :EXPLICIT, asn1data)
    assert_equal(1, asn1data.value.size)
    int = asn1data.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    
    der = asn1.to_der
    p = template.parse(der)
    
    assert_equal(1, p.a)
    assert_equal(der, p.to_der)
  end
  
  def test_asn1_sequence_of_primitive
    check_asn1_constructive_of_primitive(:asn1_sequence_of, OpenSSL::ASN1::SEQUENCE)
  end
  
  def test_asn1_set_of_primitive
    check_asn1_constructive_of_primitive(:asn1_set_of, OpenSSL::ASN1::SET)
  end
  
  def test_asn1_sequence_of_template
    check_constructive_of_template(:asn1_sequence_of, OpenSSL::ASN1::Sequence)    
  end
  
  def test_asn1_set_of_template
    check_constructive_of_template(:asn1_set_of, OpenSSL::ASN1::Set)    
  end
  
  def test_asn1_sequence_of_tagged_implicit_primitive
    check_constructive_of_tagged_primitive(:asn1_sequence_of, OpenSSL::ASN1::Sequence, :IMPLICIT)
  end
  
  def test_asn1_set_of_tagged_implicit_primitive
    check_constructive_of_tagged_primitive(:asn1_set_of, OpenSSL::ASN1::Set, :IMPLICIT)
  end
  
  def test_asn1_sequence_of_tagged_explicit_primitive
    check_constructive_of_tagged_primitive(:asn1_sequence_of, OpenSSL::ASN1::Sequence, :EXPLICIT)
  end
  
  def test_asn1_set_of_tagged_explicit_primitive
    check_constructive_of_tagged_primitive(:asn1_set_of, OpenSSL::ASN1::Set, :EXPLICIT)
  end
  
  def test_asn1_sequence_of_tagged_implicit_template
    check_constructive_of_tagged_template(:asn1_sequence_of, OpenSSL::ASN1::Sequence, :IMPLICIT)
  end
  
  def test_asn1_set_of_tagged_implicit_template
    check_constructive_of_tagged_template(:asn1_set_of, OpenSSL::ASN1::Set, :IMPLICIT)
  end
  
  def test_asn1_sequence_of_tagged_explicit_template
    check_constructive_of_tagged_template(:asn1_sequence_of, OpenSSL::ASN1::Sequence, :EXPLICIT)
  end
  
  def test_asn1_set_of_tagged_explicit_template
    check_constructive_of_tagged_template(:asn1_set_of, OpenSSL::ASN1::Set, :EXPLICIT)
  end
  
  def test_asn1_any_primitive
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
  
  def test_asn1_any_constructed
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_any :a
      end
    end
    
    t = template.new
    t.a = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1)])
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    seq = asn1.value.first
    assert_universal(OpenSSL::ASN1::SEQUENCE, seq)
    assert_equal(1, seq.value.size)
    asn1int = seq.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, asn1int)
    assert_equal(1, asn1int.value)
    
    der = asn1.to_der
    p = template.parse(OpenSSL::ASN1.decode(der))
    
    assert_equal(true, p.a.is_a?(OpenSSL::ASN1::Sequence))
    assert_universal(OpenSSL::ASN1::SEQUENCE, p.a)
    assert_equal(1, p.a.value.size)
    int = p.a.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    assert_equal(der, p.to_der)
  end
  
  def test_asn1_any_tagged_implicit
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
  
  def test_asn1_any_tagged_explicit
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_any :a, { tag: 0, tagging: :EXPLICIT}
      end
    end
    
    t = template.new
    t.a = OpenSSL::ASN1::Integer.new(1)
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    asn1data = asn1.value.first
    assert_tagged(0, :EXPLICIT, asn1data)
    assert_equal(1, asn1data.value.size)
    asn1int = asn1data.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, asn1int)
    assert_equal(1, asn1int.value)
    
    der = asn1.to_der
    p = template.parse(OpenSSL::ASN1.decode(der))
    
    assert_equal(true, p.a.is_a?(OpenSSL::ASN1::ASN1Data))
    assert_tagged(0, nil, p.a)
    assert_equal(1, p.a.value.size)
    int = p.a.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    assert_equal(der, p.to_der)
  end
  
  def test_asn1_any_default
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_any :a, { default: OpenSSL::ASN1::Integer.new(1) }
      end
    end
    
    t = template.new
    asn1 = t.to_asn1
    
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    int = asn1.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    
    p = template.parse(asn1.to_der)
    aint = p.a
    assert_universal(OpenSSL::ASN1::INTEGER, aint)
    assert_equal(1, aint.value)
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
  
  def test_asn1_template_implicitly_tagged
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    container = Class.new do
      include OpenSSL::ASN1::Template
        
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_template template, :a, { tag: 0, tagging: :IMPLICIT }
      end
    end
    
    c = container.new
    c.a.a = 1
    asn1 = c.to_asn1
    
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    seq = asn1.value.first
    assert_tagged(0, :IMPLICIT, seq)
    assert_equal(1, seq.value.size)
    int = seq.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    
    der = asn1.to_der
    p = container.parse(der)
    assert_equal(1, p.a.a)
    assert_equal(der, p.to_der)
  end
  
  def test_asn1_template_explicitly_tagged
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    container = Class.new do
      include OpenSSL::ASN1::Template
        
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_template template, :a, { tag: 0, tagging: :EXPLICIT }
      end
    end
    
    c = container.new
    c.a.a = 1
    asn1 = c.to_asn1
    
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    asn1data = asn1.value.first
    assert_tagged(0, :EXPLICIT, asn1data)
    assert_equal(1, asn1data.value.size)
    asn1seq = asn1data.value.first
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1seq)
    assert_equal(1, asn1seq.value.size)
    int = asn1seq.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    
    der = asn1.to_der
    p = container.parse(der)
    assert_equal(1, p.a.a)
    assert_equal(der, p.to_der)
  end
  
  def test_asn1_template_optional
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    container = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_template template, :a, { optional: true }
        asn1_boolean :b
        asn1_template template, :c, { optional: true, tag: 0, tagging: :EXPLICIT }
        asn1_template template, :d, { optional: true, tag: 1, tagging: :EXPLICIT }
        asn1_integer :e
      end
    end
    
    c1 = container.new
    c1.b = true
    c1.e = 1
    
    p1 = container.parse(c1.to_der)
    assert_nil(p1.a)
    assert_equal(true, p1.b)
    assert_nil(p1.c)
    assert_nil(p1.d)
    assert_equal(1, p1.e)
    
    t2 = template.new
    t2.a = 2
    c2 = container.new
    c2.b = true
    c2.c = t2
    c2.e = 2
    
    p2 = container.parse(c2.to_der)
    assert_nil(p2.a)
    assert_equal(true, p2.b)
    assert_equal(2, p2.c.a)
    assert_nil(p2.d)
    assert_equal(2, p2.e)
    
    t3 = template.new
    t3.a = 3
    c3 = container.new
    c3.b = true
    c3.d = t3
    c3.e = 3
    
    p3 = container.parse(c3.to_der)
    assert_nil(p3.a)
    assert_equal(true, p3.b)
    assert_equal(3, p3.d.a)
    assert_nil(p3.c)
    assert_equal(3, p3.e)
    
    t4 = template.new
    t4.a = 4
    c4 = container.new
    c4.a = t4
    c4.b = true
    c4.c = t4
    c4.d = t4
    c4.e = 4
    
    p4 = container.parse(c4.to_der)
    assert_equal(4, p4.a.a)
    assert_equal(true, p4.b)
    assert_equal(4, p4.c.a)
    assert_equal(4, p4.d.a)
    assert_equal(4, p4.e)
  end
  
  def test_asn1_choice_int
    check_asn1_choice_int_bool(OpenSSL::ASN1::Integer, 1)
  end
  
  def test_asn1_choice_bool
    check_asn1_choice_int_bool(OpenSSL::ASN1::Boolean, true)
  end
  
  def test_implicitly_tagged_choice_0
    check_tagged_choice(0, :IMPLICIT)
  end
  
  def test_implicitly_tagged_choice_1
    check_tagged_choice(1, :IMPLICIT)
  end
  
  def test_explicitly_tagged_choice_0
    check_tagged_choice(0, :EXPLICIT)
  end
  
  def test_explicitly_tagged_choice_1
    check_tagged_choice(1, :EXPLICIT)
  end
  
  def test_choice_templates0_explicit
    check_choice_templates(0, :EXPLICIT)
  end
  
  def test_choice_templates0_implicit
    check_choice_templates(0, :IMPLICIT)
  end
  
  def test_choice_templates1_explicit
    check_choice_templates(1, :EXPLICIT)
  end
  
  def test_choice_templates1_implicit
    check_choice_templates(1, :IMPLICIT)
  end
  
  def test_choice_any_primitive
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_choice :a do
          asn1_any
        end
      end
    end
    
    t = template.new
    t.a = OpenSSL::ASN1::Template::ChoiceValue.new(
          OpenSSL::ASN1::ASN1Data, OpenSSL::ASN1::Integer.new(1))
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    val = asn1.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, val)
    assert_equal(1, val.value)
    
    der = asn1.to_der
    p = template.parse(der)
    cv = p.a
    assert_equal(OpenSSL::ASN1::ASN1Data, cv.type)
    assert_nil(cv.tag)
    assert_universal(OpenSSL::ASN1::INTEGER, cv.value)
    assert_equal(1, cv.value.value)
    assert_equal(der, p.to_der)
  end
  
  def test_choice_any_constructed
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_choice :a do
          asn1_any
        end
      end
    end
    
    t = template.new
    t.a = OpenSSL::ASN1::Template::ChoiceValue.new(
      OpenSSL::ASN1::ASN1Data, 
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1)]))
      
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    seq = asn1.value.first
    assert_universal(OpenSSL::ASN1::SEQUENCE, seq)
    assert_equal(1, seq.value.size)
    val = seq.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, val)
    assert_equal(1, val.value)
    
    der = asn1.to_der
    p = template.parse(der)
    cv = p.a
    assert_equal(OpenSSL::ASN1::ASN1Data, cv.type)
    assert_nil(cv.tag)
    assert_universal(OpenSSL::ASN1::SEQUENCE, cv.value)
    assert_equal(1, cv.value.value.size)
    int = cv.value.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    assert_equal(der, p.to_der)
  end
  
  def test_choice_any_and_primitives0
    check_choice_any_and_primitives(OpenSSL::ASN1::Integer, OpenSSL::ASN1::Integer, 1)
  end
  
  def test_choice_any_and_primitives1
    check_choice_any_and_primitives(OpenSSL::ASN1::ASN1Data, OpenSSL::ASN1::PrintableString, 'a')
  end
  
  def test_choice_any_and_primitives2
    check_choice_any_and_primitives(OpenSSL::ASN1::Boolean, OpenSSL::ASN1::Boolean, true)
  end
  
  def test_asn1_choice_sequence_of
    check_choice_cons_of(:asn1_sequence_of, OpenSSL::ASN1::Sequence)
  end
  
  def test_asn1_choice_set_of
    check_choice_cons_of(:asn1_set_of, OpenSSL::ASN1::Set)
  end
  
  def test_default_primitive_encode
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a, { default: 1 }
      end
    end
    
    t = template.new
    asn1 = t.to_asn1
    
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    int = asn1.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    
    der = asn1.to_der
    p = template.parse(der)
    assert_equal(1, p.a)
    assert_equal(der, p.to_der)
  end
  
  def test_default_primitive_parse
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_object_id :a
        asn1_integer :b, { default: 1 }
        asn1_ia5_string :c, { optional: true }
      end
    end
    
    helper = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_object_id :a
        asn1_ia5_string :c, { optional: true }
      end
    end
    
    h = helper.new
    h.a = "1.2.3.4.5"
    asn1 = h.to_asn1
    
    p = template.parse(asn1.to_der)
    assert_nil(p.c)
    assert_equal(1, p.b)
    assert_equal("1.2.3.4.5", p.a)
    
    h = helper.new
    h.a = "1.2.3.4.5"
    h.c = "a"
    asn1 = h.to_asn1
    
    p = template.parse(asn1.to_der)
    assert_equal("a", p.c)
    assert_equal(1, p.b)
    assert_equal("1.2.3.4.5", p.a)
  end
  
  def test_default_primitive_parse_at_end
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_object_id :a
        asn1_ia5_string :b, { optional: true }
        asn1_integer :c, { default: 1 }
      end
    end

    helper = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_object_id :a
        asn1_ia5_string :b, { optional: true }
      end
    end
    
    h = helper.new
    h.a = "1.2.3.4.5"
    asn1 = h.to_asn1
    
    p = template.parse(asn1.to_der)
    assert_nil(p.b)
    assert_equal(1, p.c)
    assert_equal("1.2.3.4.5", p.a)
    
    h = helper.new
    h.a = "1.2.3.4.5"
    h.b = "a"
    asn1 = h.to_asn1
    
    p = template.parse(asn1.to_der)
    assert_equal("a", p.b)
    assert_equal(1, p.c)
    assert_equal("1.2.3.4.5", p.a)
  end
  
  def test_default_sequence_of
    check_default_cons_of(:asn1_sequence_of)
  end
  
  def test_default_set_of
    check_default_cons_of(:asn1_set_of)
  end
    
  def test_default_sequence_of_parse
    check_default_cons_of_parse(:asn1_sequence_of)
  end
  
  def test_default_set_of_parse
    check_default_cons_of_parse(:asn1_set_of)
  end
  
  def test_default_template
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end

    deff = template.new
    deff.a = 1

    container = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_template template, :a, { default: deff }
      end
    end

    c = container.new
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

  def test_default_template_parse
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end

    deff = template.new
    deff.a = 1

    container = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_boolean :a
        asn1_template template, :b, { default: deff }
      end
    end
    
    helper = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_boolean :a
      end
    end

    h = helper.new
    h.a = true
    
    p = container.parse(h.to_der)
    assert_equal(true, p.a)
    assert_equal(1, p.b.a)
  end
  
  def test_default_between_optionals
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_printable_string :a, { optional: true }
        asn1_integer :b, { default: 1 }
        asn1_octet_string :c, { optional: true }
      end
    end

    t = template.new
    asn1 = t.to_asn1

    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    int = asn1.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)

    der = asn1.to_der
    p = template.parse(der)
    assert_equal(1, p.b)
    assert_nil(p.a)
    assert_nil(p.c)
    assert_equal(der, p.to_der)
  end

  def test_default_optional_in_front
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_printable_string :a, { optional: true }
        asn1_integer :b, { default: 1 }
        asn1_octet_string :c
      end
    end

    t = template.new
    t.c = "\x01"
    asn1 = t.to_asn1

    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(2, asn1.value.size)
    int = asn1.value[0]
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    oct = asn1.value[1]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct)
    assert_equal("\x01", oct.value)

    der = asn1.to_der
    p = template.parse(der)
    assert_equal(1, p.b)
    assert_nil(p.a)
    assert_equal("\x01", p.c)
    assert_equal(der, p.to_der)
  end

  def test_default_optional_after
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_printable_string :a
        asn1_integer :b, { default: 1 }
        asn1_octet_string :c, { optional: true }
      end
    end

    t = template.new
    t.a = "a"
    asn1 = t.to_asn1

    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(2, asn1.value.size)
    str = asn1.value[0]
    assert_universal(OpenSSL::ASN1::PRINTABLESTRING, str)
    assert_equal("a", str.value)
    int = asn1.value[1]
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)


    der = asn1.to_der
    p = template.parse(der)
    assert_equal(1, p.b)
    assert_equal("a", p.a)
    assert_equal(der, p.to_der)
  end

  def test_default_at_beginning
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a, { default: 1 }
        asn1_printable_string :b
      end
    end

    t = template.new
    t.b = "b"
    asn1 = t.to_asn1

    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(2, asn1.value.size)
    int = asn1.value[0]
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    str = asn1.value[1]
    assert_universal(OpenSSL::ASN1::PRINTABLESTRING, str)
    assert_equal("b", str.value)


    der = asn1.to_der
    p = template.parse(der)
    assert_equal(1, p.a)
    assert_equal("b", p.b)
    assert_equal(der, p.to_der)
  end

  def test_default_at_end
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_printable_string :a
        asn1_integer :b, { default: 1 }
      end
    end

    t = template.new
    t.a = "a"
    asn1 = t.to_asn1

    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(2, asn1.value.size)
    str = asn1.value[0]
    assert_universal(OpenSSL::ASN1::PRINTABLESTRING, str)
    assert_equal("a", str.value)
    int = asn1.value[1]
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)


    der = asn1.to_der
    p = template.parse(der)
    assert_equal(1, p.b)
    assert_equal("a", p.a)
    assert_equal(der, p.to_der)
  end

  def test_infinite_length_declared_sequence
     check_infinite_length_declared(OpenSSL::ASN1::Sequence)
  end

  def test_infinite_length_declared_set
     check_infinite_length_declared(OpenSSL::ASN1::Set)
  end
  
  def test_infinite_length_template
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

    t = template.new
    t.a = 1
    t.set_infinite_length(true)
    c = container.new
    c.a = t
    c.set_infinite_length(true)
    
    asn1 = c.to_asn1
    assert_universal_infinite(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(2, asn1.value.size)
    seq = asn1.value[0]
    assert_universal_infinite(OpenSSL::ASN1::SEQUENCE, seq)
    assert_equal(2, seq.value.size)
    int = seq.value[0]
    assert_equal(1, int.value)
    assert_universal(OpenSSL::ASN1::EOC, seq.value[1])
    assert_universal(OpenSSL::ASN1::EOC, asn1.value[1])
    
    der = asn1.to_der
    p = container.parse(der)
    assert_equal(true, p.instance_variable_get(:@infinite_length))
    pt = p.a 
    assert_equal(true, pt.instance_variable_get(:@infinite_length))
    assert_equal(1, pt.a)
    assert_equal(der, p.to_der)
  end

  def test_infinite_length_prim_chunksize
    check_infinite_length_prim(2)
  end
  
  def test_infinite_length_prim_sizes
    check_infinite_length_prim([2, 2, 1])
  end
  
  def test_infinite_length_default
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_octet_string :a
      end
    end

    t = template.new
    words = %w{ 01 }
    single_byte = [words.join('')].pack('H*')
    bytes = single_byte * 4096
    bval = bytes + single_byte
    t.a = bval
    t.set_infinite_length_iv(:a, true)
    asn1 = t.to_asn1    

    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    cons = asn1.value[0]
    assert_universal_infinite(OpenSSL::ASN1::OCTET_STRING, cons)
    assert_equal(3, cons.value.size)
    oct1 = cons.value[0]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct1)
    assert_equal(4096, oct1.value.bytesize)
    assert_equal(bytes, oct1.value)
    oct2 = cons.value[1]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct2)
    assert_equal(1, oct2.value.bytesize)
    assert_equal(single_byte, oct2.value)
    assert_universal(OpenSSL::ASN1::EOC, cons.value[2])

    der = asn1.to_der
    p = template.parse(der)
    assert_equal(bval, p.a)
    assert_equal(true, p.a.instance_variable_get(:@infinite_length))
    inf_length_sizes = p.a.instance_variable_get(:@infinite_length_sizes)
    assert_equal([4096, 1], inf_length_sizes)
    assert_equal(der, p.to_der)
  end
  
  def test_infinite_length_prim_chunk_size_implicit
    check_infinite_length_prim_tagged(:IMPLICIT, 2)
  end
  
  def test_infinite_length_prim_chunk_size_explicit
    check_infinite_length_prim_tagged(:EXPLICIT, 2)
  end
  
  def test_infinite_length_prim_sizes_implicit
    check_infinite_length_prim_tagged(:IMPLICIT, [2, 2, 1])
  end
  
  def test_infinite_length_prim_sizes_explicit
    check_infinite_length_prim_tagged(:EXPLICIT, [2, 2, 1])
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
  
  def test_optional_constructive_of
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
        asn1_set_of OpenSSL::ASN1::Integer, :b, { optional: true }
        asn1_boolean :c
        asn1_sequence_of OpenSSL::ASN1::Integer, :d, { optional: true }
      end
    end
    
    t1 = template.new
    t1.a = 1
    t1.c = true
    p1 = template.parse(t1.to_der)
    assert_equal(1, p1.a)
    assert_nil(p1.b)
    assert_equal(true, p1.c)
    assert_nil(p1.d)
  end
  
  def test_optional_not_inherited_template
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_printable_string :a, { optional: true }
        asn1_integer :b
      end
    end
    
    container = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_template template, :a, { optional: true }
        asn1_integer :b
      end
    end
    
    c1 = container.new
    c1.b = 1
    
    p1 = container.parse(c1.to_der)
    assert_nil(p1.a)
    assert_equal(1, p1.b)
    
    t2 = template.new
    t2.b = 2
    c2 = container.new
    c2.a = t2
    c2.b = 2
    
    p2 = container.parse(c2.to_der)
    assert_nil(p2.a.a)
    assert_equal(2, p2.a.b)
    assert_equal(2, p2.b)
    
    t3 = template.new
    t3.a = 'a'
    c3 = container.new
    c3.a = t3
    c3.b = 3
    
    assert_raises(OpenSSL::ASN1::ASN1Error) do
      c3.to_der
    end
  end
  
  def test_ignore_null_on_parsing
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
        asn1_template template, :b, { optional: true }
        asn1_template template, :c, { default:  template.new }
      end
    end
    
    c = container.new
    c.a.a = 1
    assert_nil(c.b)
    assert_nil(c.c)
  end
  
  def test_instance_options_are_temporary
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    t = template.new({ tag: 0, tagging: :IMPLICIT })
    t.a = 1
    asn1 = t.to_asn1
    assert_tagged(0, :IMPLICIT, asn1)
    assert_equal(1, asn1.value.size)
    
    t2 = template.new
    t2.a = 1
    asn2 = t2.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn2)
    assert_equal(1, asn2.value.size)
  end
  
  def test_encode_decode_invariance
    helper = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a, { tag: 1, tagging: :EXPLICIT }
      end
    end
    
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_template helper, :a, { tag: 0, tagging: :EXPLICIT }
      end
    end
    
    t = template.new
    t.a.a = 1
    asn1 = t.to_asn1
    der = asn1.to_der
    
    p = template.parse(der)
    p2 = template.parse(asn1)
    
    assert_equal(p.to_der, p2.to_der)
  end
  
  def test_parse_twice
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a, { optional: true }
        asn1_choice :b do
          asn1_integer nil, { tag: 0, tagging: :EXPLICIT }
        end
        asn1_integer :c, { tag: 2, tagging: :EXPLICIT }
      end
    end
    
    t = template.new
    t.b = OpenSSL::ASN1::Template::ChoiceValue.new(OpenSSL::ASN1::Integer, 1, 0)
    t.c = 2
    t.to_asn1
    asn1 = t.to_asn1
    
    template.parse(asn1)
    template.parse(asn1.to_der)
    der = t.to_der
    p = template.parse(der)
    assert_nil(p.a)
    cv = p.b
    assert_equal(OpenSSL::ASN1::Integer, cv.type)
    assert_equal(0, cv.tag)
    assert_equal(1, cv.value)
    assert_equal(2, t.c)
    p.to_asn1
    p.to_der
    assert_equal(der, p.to_der)
  end
  
  def test_template_doesnt_match
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Set do
        asn1_integer :a
      end
    end
    
    other = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    o = other.new
    o.a = 1
    
    assert_raises(OpenSSL::ASN1::ASN1Error) do
      p = template.parse(o.to_asn1)
    end
  end

  def test_size_computation_inf_length_rest
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_octet_string :a
      end
    end

    t = template.new
    bytes = %w{ 01 02 03 04 05 }
    t.a = [bytes.join('')].pack('H*')
    t.set_infinite_length_iv(:a, true, 2)
    assert_equal(true, t.a.instance_variable_get(:@infinite_length))
    sizes = t.a.instance_variable_get(:@infinite_length_sizes)
    assert_equal([2, 2, 1], sizes)
  end

  def test_size_computation_inf_length_no_rest
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_octet_string :a
      end
    end

    t = template.new
    bytes = %w{ 01 02 03 04 }
    t.a = [bytes.join('')].pack('H*')
    t.set_infinite_length_iv(:a, true, 2)
    assert_equal(true, t.a.instance_variable_get(:@infinite_length))
    sizes = t.a.instance_variable_get(:@infinite_length_sizes)
    assert_equal([2, 2], sizes)
  end

  private
  
  def assert_universal(tag, asn1)
    do_assert_universal(tag, asn1, false)
  end

  def assert_universal_infinite(tag, asn1)
    do_assert_universal(tag, asn1, true)
  end

  def do_assert_universal(tag, asn1, inf_length)
    assert_equal(tag, asn1.tag)
    assert_equal(inf_length, asn1.infinite_length)
    if asn1.respond_to?(:tagging)
      assert_nil(asn1.tagging)
    end
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
  
  def check_constructive_of_template(cons_declare, type)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    container = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        send(cons_declare, template, :a)
      end
    end
    
    t0 = template.new
    t0.a = 1
    t1 = template.new
    t1.a = 2
    c = container.new
    c.a = [ t0, t1 ]
    
    asn1 = c.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    seq = asn1.value.first
    assert_universal(OpenSSL::ASN1::CLASS_TAG_MAP[type], seq)
    assert_equal(2, seq.value.size)
    i = 1
    seq.value.each do |templ|
      assert_universal(OpenSSL::ASN1::SEQUENCE, templ)
      assert_equal(1, templ.value.size)
      int = templ.value.first
      assert_universal(OpenSSL::ASN1::INTEGER, int)
      assert_equal(i, int.value)
      i += 1
    end
    
    der = asn1.to_der
    p = container.parse(der)
    
    assert_equal(2, p.a.size)
    assert_equal(1, p.a[0].a)
    assert_equal(2, p.a[1].a)
    assert_equal(der, p.to_der)
  end
  
  def check_constructive_of_tagged_primitive(cons_declare, type, tagging)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        send(cons_declare, OpenSSL::ASN1::Integer, :a, { tag: 0, tagging: tagging })
      end
    end
    
    t = template.new
    t.a = [ 0, 1 ]
    
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    wrap = asn1.value.first
    assert_tagged(0, tagging, wrap)
    
    if tagging == :IMPLICIT
      seq = wrap
    else
      assert_equal(1, wrap.value.size)
      seq = wrap.value.first
      assert_universal(OpenSSL::ASN1::CLASS_TAG_MAP[type], seq)
    end
    
    assert_equal(2, seq.value.size)
    i = 0
    seq.value.each do |int|
      assert_universal(OpenSSL::ASN1::INTEGER, int)
      assert_equal(i, int.value)
      i += 1
    end
  end
  
  def check_constructive_of_tagged_template(cons_declare, type, tagging)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    container = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        send(cons_declare, template, :a, { tag: 0, tagging: tagging })
      end
    end
    
    t0 = template.new
    t0.a = 1
    t1 = template.new
    t1.a = 2
    c = container.new
    c.a = [ t0, t1 ]
    
    asn1 = c.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    wrap = asn1.value.first
    assert_tagged(0, tagging, wrap)
    
    if tagging == :IMPLICIT
      seq = wrap
    else
      assert_equal(1, wrap.value.size)
      seq = wrap.value.first
      assert_universal(OpenSSL::ASN1::CLASS_TAG_MAP[type], seq)
    end
    
    assert_equal(2, seq.value.size)
    i = 1
    seq.value.each do |templ|
      assert_universal(OpenSSL::ASN1::SEQUENCE, templ)
      assert_equal(1, templ.value.size)
      int = templ.value.first
      assert_universal(OpenSSL::ASN1::INTEGER, int)
      assert_equal(i, int.value)
      i += 1
    end
    
    der = asn1.to_der
    p = container.parse(der)
    
    assert_equal(2, p.a.size)
    assert_equal(1, p.a[0].a)
    assert_equal(2, p.a[1].a)
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
  
  def check_tagged_choice(tag, tagging)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_choice :a do
          asn1_integer nil, { tag: 0, tagging: tagging }
          asn1_integer nil, { tag: 1, tagging: tagging }
        end
      end
    end
    
    t = template.new
    t.a = OpenSSL::ASN1::Template::ChoiceValue.new(OpenSSL::ASN1::Integer, 1, tag)
    
    asn1 = t.to_asn1
    check_tagged_choice_tagging(asn1, tag, tagging)
    der = asn1.to_der
    
    p = template.parse(der)
    cv = p.a
    assert_equal(OpenSSL::ASN1::Integer, cv.type)
    assert_equal(1, cv.value)
    assert_equal(tag, cv.tag)
    assert_equal(der, p.to_der)
  end
  
  def check_tagged_choice_tagging(asn1, tag, tagging)
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    if tagging == :IMPLICIT
      int = asn1.value.first
      assert_tagged(tag, tagging, int)
    else
      asn1data = asn1.value.first
      assert_tagged(tag, tagging, asn1data)
      assert_equal(1, asn1data.value.size)
      int = asn1data.value.first
      assert_universal(OpenSSL::ASN1::INTEGER, int)
    end
    assert_equal(1, int.value)
  end
  
  def check_choice_templates(tag, tagging)
    template1 = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    template2 = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :a
      end
    end
    
    container = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_choice :choice do
          asn1_template template1, nil, { tag: 0, tagging: tagging }
          asn1_template template2, nil, { tag: 1, tagging: tagging }
        end
      end
    end
    
    c = container.new
    
    type = if tag == 0
      template1
    else
      template2
    end
    
    t = type.new
    t.a = 1
    
    c.choice = OpenSSL::ASN1::Template::ChoiceValue.new(type, t, tag)
    asn1 = c.to_asn1
    check_choice_templates_tagging(asn1, tag, tagging)
    der = asn1.to_der
    
    p = container.parse(der)
    cv = p.choice
    assert_equal(type, cv.type)
    assert_equal(1, cv.value.a)
    assert_equal(tag, cv.tag)
    assert_equal(der, p.to_der)
  end
  
  def check_choice_templates_tagging(asn1, tag, tagging)
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    if tagging == :IMPLICIT
      seq = asn1.value.first
      assert_tagged(tag, tagging, seq)
    else
      asn1data = asn1.value.first
      assert_tagged(tag, tagging, asn1data)
      assert_equal(1, asn1data.value.size)
      seq = asn1data.value.first
      assert_universal(OpenSSL::ASN1::SEQUENCE, seq)
    end
    assert_equal(1, seq.value.size)
    int = seq.value.first
    assert_equal(1, int.value)
  end
  
  def check_choice_any_and_primitives(choice_type, type, value)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_choice :a do
          asn1_integer
          asn1_any
          asn1_boolean
        end
      end
    end
    
    t = template.new
    if choice_type == OpenSSL::ASN1::ASN1Data
      v = type.new(value)
    else
      v = value
    end
    
    t.a = OpenSSL::ASN1::Template::ChoiceValue.new(choice_type, v)
    asn1 = t.to_asn1
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    val = asn1.value.first
    assert_universal(OpenSSL::ASN1::CLASS_TAG_MAP[type], val)
    assert_equal(value, val.value)
    
    der = asn1.to_der
    p = template.parse(der)
    cv = p.a
    assert_equal(choice_type, cv.type)
    assert_nil(cv.tag)
    if choice_type == OpenSSL::ASN1::ASN1Data
      assert_universal(OpenSSL::ASN1::CLASS_TAG_MAP[type], cv.value)
      assert_equal(value, cv.value.value)
    else
      assert_equal(value, cv.value)
    end
    assert_equal(der, p.to_der)
  end
  
  def check_choice_cons_of(cons_declare, type)
    template = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :b
      end
    end
    
    container = Class.new do
      include OpenSSL::ASN1::Template
      
      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_choice :a do
          send(cons_declare, template)
        end
      end
    end
    
    t1 = template.new
    t1.b = 1
    t2 = template.new
    t2.b = 2
    
    c = container.new
    c.a = OpenSSL::ASN1::Template::ChoiceValue.new(template, [t1, t2])
    asn1 = c.to_asn1
    
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    seq = asn1.value.first
    assert_universal(OpenSSL::ASN1::CLASS_TAG_MAP[type], seq)
    assert_equal(2, seq.value.size)
    seq1 = seq.value[0]
    assert_universal(OpenSSL::ASN1::SEQUENCE, seq1)
    assert_equal(1, seq1.value.size)
    int1 = seq1.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int1)
    assert_equal(1, int1.value)
    seq2 = seq.value[1]
    assert_universal(OpenSSL::ASN1::SEQUENCE, seq2)
    assert_equal(1, seq2.value.size)
    int2 = seq2.value.first
    assert_universal(OpenSSL::ASN1::INTEGER, int2)
    assert_equal(2, int2.value)
  end
  
  def check_default_cons_of(cons_declare)
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        send(cons_declare, OpenSSL::ASN1::Boolean, :a, { default: [true, false] })
        asn1_integer :b
      end
    end
    
    t = template.new
    t.b = 1
    
    p = template.parse(t.to_asn1)
    
    assert_equal(2, p.a.size)
    assert_equal(true, p.a[0])
    assert_equal(false, p.a[1])
    assert_equal(1, p.b)
  end
  
  def check_default_cons_of_parse(cons_declare)
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        send(cons_declare, OpenSSL::ASN1::Boolean, :a, { default: [true, false] })
        asn1_integer :b
      end
    end
    
    helper = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_integer :b
      end
    end

    h = helper.new
    h.b = 1
    
    p = template.parse(h.to_asn1)
    
    assert_equal(2, p.a.size)
    assert_equal(true, p.a[0])
    assert_equal(false, p.a[1])
    assert_equal(1, p.b)
  end

  def check_infinite_length_declared(cons)
     template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare cons do
        asn1_integer :a
      end
     end

    t = template.new
    t.a = 1
    t.set_infinite_length(true)
    asn1 = t.to_asn1
    assert_universal_infinite(OpenSSL::ASN1::CLASS_TAG_MAP[cons], asn1)
    assert_equal(2, asn1.value.size)
    int = asn1.value[0]
    assert_universal(OpenSSL::ASN1::INTEGER, int)
    assert_equal(1, int.value)
    eoc = asn1.value[1]
    assert_universal(OpenSSL::ASN1::EOC, eoc)

    der = asn1.to_der
    p = template.parse(der)
    assert_equal(true, p.instance_variable_get(:@infinite_length))
    assert_equal(1, p.a)
    assert_equal(der, p.to_der)
  end
  
  def check_infinite_length_prim(sizes)
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_octet_string :a
      end
    end

    t = template.new
    words = %w{ 01 02 03 04 05 }
    bytes = [words.join('')].pack('H*')
    t.a = bytes
    t.set_infinite_length_iv(:a, true, sizes)
    asn1 = t.to_asn1

    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    cons = asn1.value[0]
    assert_universal_infinite(OpenSSL::ASN1::OCTET_STRING, cons)
    assert_equal(4, cons.value.size)
    oct1 = cons.value[0]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct1)
    assert_equal([%w{ 01 02 }.join('')].pack('H*'), oct1.value)
    oct2 = cons.value[1]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct2)
    assert_equal([%w{ 03 04 }.join('')].pack('H*'), oct2.value)
    oct3 = cons.value[2]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct3)
    assert_equal([%w{ 05 }.join('')].pack('H*'), oct3.value)
    assert_universal(OpenSSL::ASN1::EOC, cons.value[3])

    der = asn1.to_der
    p = template.parse(der)
    assert_equal(bytes, p.a)
    assert_equal(true, p.a.instance_variable_get(:@infinite_length))
    inf_length_sizes = p.a.instance_variable_get(:@infinite_length_sizes)
    assert_equal([2, 2, 1], inf_length_sizes)
    assert_equal(der, p.to_der)
  end
  
  def check_infinite_length_prim_tagged(tagging, sizes)
    template = Class.new do
      include OpenSSL::ASN1::Template

      asn1_declare OpenSSL::ASN1::Sequence do
        asn1_octet_string :a, { tag: 0, tagging: tagging }
      end
    end

    t = template.new
    words = %w{ 01 02 03 04 05 }
    bytes = [words.join('')].pack('H*')
    t.a = bytes
    t.set_infinite_length_iv(:a, true, sizes)
    asn1 = t.to_asn1
    
    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1)
    assert_equal(1, asn1.value.size)
    cons = asn1.value[0]
    assert_equal(0, cons.tag)
    assert_equal(true, cons.infinite_length)
    assert_equal(tagging, cons.tagging) if tagging == :IMPLICIT
    assert_equal(:CONTEXT_SPECIFIC, cons.tag_class)
    if tagging == :EXPLICIT
      assert_equal(2, cons.value.size)
      assert_universal_infinite(OpenSSL::ASN1::OCTET_STRING, cons.value[0])
      assert_universal(OpenSSL::ASN1::EOC, cons.value[1])
      cons = cons.value[0]
    else
      
    end
    
    assert_equal(4, cons.value.size)
    oct1 = cons.value[0]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct1)
    assert_equal([%w{ 01 02 }.join('')].pack('H*'), oct1.value)
    oct2 = cons.value[1]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct2)
    assert_equal([%w{ 03 04 }.join('')].pack('H*'), oct2.value)
    oct3 = cons.value[2]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct3)
    assert_equal([%w{ 05 }.join('')].pack('H*'), oct3.value)
    assert_universal(OpenSSL::ASN1::EOC, cons.value[3])

    der = asn1.to_der
    p = template.parse(der)
    assert_equal(bytes, p.a)
    assert_equal(true, p.a.instance_variable_get(:@infinite_length))
    inf_length_sizes = p.a.instance_variable_get(:@infinite_length_sizes)
    assert_equal([2, 2, 1], inf_length_sizes)
    assert_equal(der, p.to_der)
  end
  
end




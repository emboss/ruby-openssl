module OpenSSL::ASN1::Template
  #Every encoder needs to construct a subtype of 
  #OpenSSL::ASN1::ASN1Data from the definition that
  #is passed, and possible the instance variable
  #that can be retrieved from definition[:name]
  #Tags, tagging and infinite_length
  #must be set according to the values in the 
  #definition. Finally the to_asn1 method must
  #return the ASN1Data value. If the corresponding
  #data in the template is nil, then nil shall also
  #be returned.
  module Encoder
    class << self
      def to_asn1_obj(obj, definition)
        definition[:encoder].to_asn1(obj, definition)
      end
    end
  end
  
  module TypeEncoder 
    def type_new(value, type, tag, tagging, inf_length=nil, tag_class=nil)
      unless tag
        val = type.new(value)
        val.infinite_length = true if inf_length
        val
      else
        tag_class = tag_class || determine_tag_class(tag)
        encode_explicit(value, type, tag, tagging, tag_class, inf_length)
      end
    end
  
    def encode_explicit(value, type, tag, tagging, tag_class, inf_length)
      if tagging == :EXPLICIT
        inner = type.new(value)
        inner.infinite_length = true if inf_length
        val = OpenSSL::ASN1::ASN1Data.new([inner], tag, tag_class)
        val.infinite_length = true if inf_length
      else
        val = type.new(value, tag, tagging, tag_class)
        val.infinite_length = true if inf_length
      end
      val
    end
    
    def value_raise_or_default(value, name, options)
      optional = options[:optional]
      default = options[:default]
      
      unless value
        unless optional || default != nil
          raise OpenSSL::ASN1::ASN1Error.new(
          "Mandatory value #{name} not set.")
        end
        default
      else
        value
      end  
    end
  end
  
  class PrimitiveEncoder
    class << self
      include TypeEncoder, TemplateUtil
      
      def to_asn1(obj, definition)
        options = definition[:options]
        type = definition[:type]
        tag = options[:tag]
        tagging = options[:tagging]
        name = definition[:name]

        if type == OpenSSL::ASN1::Null
          return nil if options[:optional]
          return type_new(nil, type, tag, tagging)
        end

        val = obj.send(name)
        value = value_raise_or_default(val, name, options)
        return nil if value == nil

        if value.instance_variable_get(:@infinite_length)
          return PrimitiveEncoderInfinite.to_asn1(obj, definition)
        end

        type_new(value, type, tag, tagging)
      end
    end
  end
      
  class PrimitiveEncoderInfinite
    class << self
      include TypeEncoder, TemplateUtil

      DEFAULT_CHUNK_SIZE = 4096

      def to_asn1(obj, definition)
        options = definition[:options]
        type = definition[:type] 
        tag = options[:tag]
        tag_class = determine_tag_class(tag)

        tagging = options[:tagging]
        name = definition[:name]
        val = obj.send(name)
        value = value_raise_or_default(val, name, options)
        return nil if value == nil
        
        cons_value = encode_value(value, type)
        
        encode_inf_explicit(cons_value,
                            default_tag_of_type(type),
                            tag, 
                            tagging, 
                            tag_class)
      end

      private

      def encode_value(value, type)
        inf_length_sizes = value.instance_variable_get(:@infinite_length_sizes)
        if inf_length_sizes
          encode_with_sizes(value, type, inf_length_sizes)
        else
          encode_with_chunk_size(value, type, DEFAULT_CHUNK_SIZE)
        end
      end

      def encode_with_sizes(value, type, sizes)
        offset = 0
        cons_value = Array.new
        sizes.each do |chunk|
          cons_value << type.new(value[offset, chunk])
          offset += chunk
        end
        cons_value << OpenSSL::ASN1::EndOfContent.new
        cons_value
      end

      def encode_with_chunk_size(value, type, size)
        offset = 0
        cons_value = Array.new
        val_size = value.bytesize
        this_many = val_size / size
        this_many.times do
          cons_value << type.new(value[offset, size])
          offset += size
        end
        rest = val_size - (this_many * size)
        cons_value << type.new(value[offset, rest]) if rest
        cons_value << OpenSSL::ASN1::EndOfContent.new
        cons_value
      end
      
      def encode_inf_explicit(value, default_tag, tag, tagging, tag_class)
        if tagging == :EXPLICIT
          inner = OpenSSL::ASN1::Constructive.new(value, default_tag)
          inner.infinite_length = true
          val = OpenSSL::ASN1::ASN1Data.new([inner, OpenSSL::ASN1::EndOfContent.new], 
                                            tag, tag_class)
          val.infinite_length = true
        else
          tag ||= default_tag
          val = OpenSSL::ASN1::Constructive.new(value, tag, tagging, tag_class)
          val.infinite_length = true
        end
        val
      end

    end
  end
        
  class ConstructiveEncoder
    class << self
      include TypeEncoder, TemplateUtil
      
      def to_asn1(obj, definition)
        options = definition[:options]
        type = definition[:type] 
        inner_def = definition[:inner_def]
        inf_length = obj.instance_variable_get(:@infinite_length)
        tag = options[:tag]
        tagging = options[:tagging]
        value = Array.new

        inner_def.each do |element|
          inner_obj = Encoder.to_asn1_obj(obj, element)
          value << inner_obj if inner_obj
        end
        
        value << OpenSSL::ASN1::EndOfContent.new if inf_length
        
        type_new(value, type, tag, tagging, inf_length)
      end
      
    end
  end
      
  class TemplateEncoder
    class << self
      include TypeEncoder, TemplateUtil
      
      def to_asn1(obj, definition)
        options = definition[:options]
        name = definition[:name]
        value = obj.send(name)
        value = value_raise_or_default(value, name, options)
        return nil if value == nil
        val_def = value.class.instance_variable_get(:@_definition).merge({ options: options })
        Encoder.to_asn1_obj(value, val_def)
      end
    end
  end

  class AnyEncoder
    class << self
      include TypeEncoder, TemplateUtil

      def to_asn1(obj, definition)
        options = definition[:options]
        tag = options[:tag]
        tag_class = determine_tag_class(tag)
        tagging = options[:tagging]
        name = definition[:name]
        value = obj.send(name)
        value = value_raise_or_default(value, name, options)
        return nil if value == nil
        inf_length = value.instance_variable_get(:@infinite_length)

        tag = tag || value.tag
        unless tagging 
          if value.respond_to?(:tagging)
            tagging = value.tagging
          end
        end

        encode_explicit(value, tag, tagging, tag_class, inf_length)
      end
      
      private
      
      def encode_explicit(value, tag, tagging, tag_class, inf_length)
        #Changing value here should be fine, it's only related to this instance,
        #not the global definition
        if tagging == :EXPLICIT
          if value.class == OpenSSL::ASN1::ASN1Data #asn1_any, already wrapped
            return value
          end
          
          #try to make inner untagged
          value.tag = default_tag(value)
          if value.respond_to?(:tagging)
            value.tagging = nil
          end
          value.tag_class = :UNIVERSAL
          outer = OpenSSL::ASN1::ASN1Data.new([value], tag, tag_class)
          if inf_length && value.respond_to?(:infinite_length=)
            value.infinite_length = true
          end
          outer.infinite_length = true if inf_length
          outer
        else
          value.tag = tag
          if value.respond_to?(:tagging)
            value.tagging = tagging
          end
          value.tag_class = tag_class
          value
        end
      end
          
      def default_tag(value)
        cls = value.class
            
        while cls do
          tag = OpenSSL::ASN1::CLASS_TAG_MAP[cls]
          return tag if tag
          cls = cls.superclass
        end
            
        raise OpenSSL::ASN1::ASN1Error.new("No universal tag found for class #{value.class}")
      end
    end
  end
      
  class SequenceOfEncoder
    class << self
      
      def to_asn1(obj, definition)
        ConstructiveOfEncoder.to_asn1(obj, definition, OpenSSL::ASN1::Sequence)
      end
    end
  end
         
  class SetOfEncoder
    class << self
          
      def to_asn1(obj, definition)
        ConstructiveOfEncoder.to_asn1(obj, definition, OpenSSL::ASN1::Set)
      end
    end
  end
      
  class ConstructiveOfEncoder
    class << self
      include TypeEncoder, TemplateUtil
          
      def to_asn1(obj, definition, type)
        options = definition[:options]
        name = definition[:name]
        inner_type = definition[:type]
        tag = options[:tag]
        tagging = options[:tagging]
        value = obj.send(name)
        value = value_raise_or_default(value, name, options)
        return nil if value == nil
        inf_length = value.instance_variable_get(:@infinite_length)

        seq_value = Array.new
        value.each do |element|
          #inner values are either template types or primitives
          elem_value = element.respond_to?(:to_asn1) ? 
                       element.to_asn1 : inner_type.new(element)
          seq_value << elem_value
        end
        type_new(seq_value, type, tag, tagging, inf_length)
      end
    end
  end
      
  class ChoiceEncoder
    class << self
      include TypeEncoder, TemplateUtil
          
      def to_asn1(obj, definition)
        options = definition[:options]
        name = definition[:name]
        val = obj.send(name)

        value = value_raise_or_default(val, name, options)
        return nil if value == nil
        unless value.is_a? ChoiceValue
          raise ArgumentError.new("ChoiceValue expected for #{name}")
        end

        tmp_def = get_definition(value, definition[:inner_def])

        if tmp_def[:encoder] == ConstructiveEncoder
          tmp_val = value.value #values to be encoded are in a helper object
        else
          tmp_def[:name] = :value
          tmp_val = value
        end

        if obj.instance_variable_get(:@infinite_length)
          tmp_val.instance_variable_set(:@infinite_length, true)
        end

        tmp_def[:encoder].to_asn1(tmp_val, tmp_def)
      end
          
      private
          
      def get_definition(choice_val, inner_def)
        inner_def.each do |deff|
          if choice_val.type == deff[:type] && choice_val.tag == deff[:options][:tag]
            return deff.merge({})
          end
        end
        raise OpenSSL::ASN1::ASN1Error.new("Found no definition for "+
          "#{choice_val.type} in Choice")
      end
    end
  end

end

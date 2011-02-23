module OpenSSL::ASN1::Template
  #Every encoder needs to construct a subtype of 
  #OpenSSL::ASN1::ASN1Data from the definition that
  #is passed, and possible the instance variable
  #that can be retrieved from definition[:name]
  #Tags, tagging and infinite_length
  #must be set according to the values in the 
  #definition. Finally the to_asn1 method must
  #return the ASN1Data value. If the corresponding
  #data in the asn1 is nil, then nil shall also
  #be returned.
  module TypeEncoder 
    def type_new(value, type, tag, tagging, inf_length=nil, tag_class=nil)
      unless tag
        val = type.new(value)
        val.infinite_length = true if inf_length
        val
      else
        encode_explicit(value, type, tag, tagging, tag_class || determine_tag_class(tag), inf_length)
      end
    end
  
    def encode_explicit(value, type, tag, tagging, tag_class, inf_length)
      if tagging == :EXPLICIT
        inner = type.new(value)
        if inf_length
          inner.infinite_length = true
          OpenSSL::ASN1::ASN1Data.new([inner, OpenSSL::ASN1::EndOfContent.new], tag, tag_class)
        else
          OpenSSL::ASN1::ASN1Data.new([inner], tag, tag_class)
        end
      else
        val = type.new(value, tag, tagging, tag_class)
        val.infinite_length = true if inf_length
        val
      end
    end
    
    def value_raise_or_default(value, name, options)
      unless value || optional(options) || default(options) != nil
        raise OpenSSL::ASN1::ASN1Error.new("Mandatory value #{name} not set.")
      end
      value
    end
  end
  
  class PrimitiveEncoder
    class << self
      include TypeEncoder, TemplateUtil
      
      def to_asn1(obj, definition)
        value = value_raise_or_default(obj.instance_variable_get(definition[:name]), definition[:name], definition[:options])
        return nil if value == nil || value == default(definition[:options])

        if value.instance_variable_get(:@infinite_length)
          return PrimitiveEncoderInfinite.to_asn1(obj, definition)
        end

        type_new(value, definition[:type], tag(definition[:options]), tagging(definition[:options]))
      end
    end
  end
      
  class PrimitiveEncoderInfinite
    class << self
      include TypeEncoder, TemplateUtil

      DEFAULT_CHUNK_SIZE = 4096

      def to_asn1(obj, definition)
        tag = tag(definition[:options])

        value = value_raise_or_default(obj.instance_variable_get(definition[:name]), definition[:name], definition[:options])
        return nil if value == nil || value == default(definition[:options])
        
        encode_inf_explicit(value.instance_variable_get(:@definite_value),
                            encode_value(value, definition[:type]),
                            default_tag_of_type(definition[:type]),
                            tag, 
                            tagging(definition[:options]),
                            determine_tag_class(tag))
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
      
      def encode_inf_explicit(single_value, value, default_tag, tag, tagging, tag_class)
        if tagging == :EXPLICIT
          if single_value
            val = OpenSSL::ASN1::ASN1Data.new(value, tag, tag_class)
          else
            inner = OpenSSL::ASN1::Constructive.new(value, default_tag)
            inner.infinite_length = true
            val = OpenSSL::ASN1::ASN1Data.new([inner, OpenSSL::ASN1::EndOfContent.new],
                                              tag, tag_class)
          end
        else
          tag ||= default_tag
          val = OpenSSL::ASN1::Constructive.new(value, tag, tagging, tag_class)
        end
        val.infinite_length = true
        val
      end

    end
  end
        
  class ConstructiveEncoder
    class << self
      include TypeEncoder, TemplateUtil
      
      def to_asn1(obj, definition)
        inf_length = obj.instance_variable_get(:@infinite_length)
        value = Array.new

        definition[:inner_def].each do |element|
          inner_obj = element[:encoder].to_asn1(obj, element)
          value << inner_obj if inner_obj
        end
        
        value << OpenSSL::ASN1::EndOfContent.new if inf_length
        
        type_new(value, definition[:type], tag(definition[:options]), tagging(definition[:options]), inf_length)
      end
      
    end
  end
      
  class TemplateEncoder
    class << self
      include TypeEncoder, TemplateUtil
      
      def to_asn1(obj, definition)
        value = value_raise_or_default(obj.instance_variable_get(definition[:name]), definition[:name], definition[:options])
        return nil if value == nil || value == default(definition[:options])
        val_def = TemplateUtil.dup_definition_with_opts(value.class.instance_variable_get(:@definition), definition[:options])
        val_def[:encoder].to_asn1(value, val_def)
      end
    end
  end

  class AnyEncoder
    class << self
      include TypeEncoder, TemplateUtil

      def to_asn1(obj, definition)
        tag = tag(definition[:options])
        tag_class = determine_tag_class(tag)

        tagging = tagging(definition[:options])
        value = value_raise_or_default(obj.instance_variable_get(definition[:name]), name, definition[:options])
        return nil if value == nil || value == default(definition[:options])

        #shortcut if value was parsed -> it has the right form already
        if value.instance_variable_get(:@parsed)
          return value
        end

        inf_length = value.instance_variable_get(:@infinite_length)
        tag = tag || value.tag
        encode(value, tag, tagging, tag_class, inf_length)
      end
      
      private
      
      def encode(value, tag, tagging, tag_class, inf_length)
        #Changing value here should be fine, it's only related to this instance,
        #not the global definition
        if tagging == :EXPLICIT
          #if value.class == OpenSSL::ASN1::ASN1Data #asn1_any, already wrapped
          #  return value
          #end
          
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
        value = value_raise_or_default(obj.instance_variable_get(definition[:name]), definition[:name], definition[:options])
        return nil if value == nil || value == default(definition[:options])
        inf_length = value.instance_variable_get(:@infinite_length)

        seq_value = definition[:type].respond_to?(:parse) ?
                    encode_templates(value) :
                    encode_primitives(value, definition[:type])
        type_new(seq_value, type, tag(definition[:options]), tagging(definition[:options]), inf_length)
      end

      private

      def encode_templates(values)
        values.map do |element|
          element.to_asn1
        end
      end

      def encode_primitives(values, type)
        values.map do |element|
          type.new(element)
        end
      end

    end
  end
      
  class ChoiceEncoder
    class << self
      include TypeEncoder, TemplateUtil
          
      def to_asn1(obj, definition)
        value = value_raise_or_default(obj.instance_variable_get(definition[:name]), definition[:name], definition[:options])
        return nil if value == nil || value == default(definition[:options])
        unless value.is_a? ChoiceValue
          raise ArgumentError.new("ChoiceValue expected for #{definition[:name]}")
        end

        tmp_def = get_definition(value, definition[:inner_def])

        if tmp_def[:encoder] == ConstructiveEncoder
          tmp_val = value.value #values to be encoded are in a helper object
        else
          tmp_def[:name] = :@value
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
          if choice_val.type == deff[:type] && choice_val.tag == tag(deff[:options])
            return deff
          end
        end
        raise OpenSSL::ASN1::ASN1Error.new("Found no definition for "+
          "#{choice_val.type} in Choice")
      end
    end
  end

  class NullEncoder
    class << self
      include TypeEncoder, TemplateUtil

      def to_asn1(obj, definition)
        return nil if optional(definition[:options])
        type_new(nil, definition[:type], tag(definition[:options]), tagging(definition[:options]))
      end
    end
  end

  class ObjectIdEncoder
    class << self
      include TypeEncoder, TemplateUtil

      def to_asn1(obj, definition)
        tag = tag(definition[:options])
        tag_class = determine_tag_class(tag)

        tagging = tagging(definition[:options])
        value = value_raise_or_default(obj.instance_variable_get(definition[:name]), definition[:name], definition[:options])
        return nil if value == nil || value == default(definition[:options])

        #shortcut if value was parsed and not explicitly tagged-> it has the right form already
        if value.instance_variable_get(:@parsed) && !tagging
          return value
        end
        tag = tag || value.tag
        encode(value, tag, tagging, tag_class)
      end

      private

      def encode(value, tag, tagging, tag_class)
        #Changing value here should be fine.
        if tagging == :EXPLICIT
          #try to make inner untagged
          value.tag = OpenSSL::ASN1::OBJECT
          value.tagging = nil
          value.tag_class = :UNIVERSAL
          OpenSSL::ASN1::ASN1Data.new([value], tag, tag_class)
        else
          value.tag = tag
          value.tagging = tagging
          value.tag_class = tag_class
          value
        end
      end

    end
  end

end

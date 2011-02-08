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
    def type_new(value, type, tag, tagging, inf_length=nil)
      unless tag
        val = type.new(value)
        val.infinite_length = true if inf_length
        val
      else
        tag_class = determine_tag_class(tag)
        encode_explicit(value, type, tag, tagging, tag_class, inf_length)
      end
    end
  
    def encode_explicit(value, type, tag, tagging, tag_class, inf_length)
      if tagging == :EXPLICIT
        inner = type.new(value)
        inner.infinite_length = true if inf_length
        val = OpenSSL::ASN1::ASN1Data.new([type.new(value)], tag, tag_class)
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
        val = obj.instance_variable_get("@" + name.to_s)

        if type == OpenSSL::ASN1::Null
          return nil if options[:optional]
          return type_new(nil, type, tag, tagging)
        end
        
        value = value_raise_or_default(val, name, options)
        return nil if value == nil

        if val.instance_variable_get(:@infinite_length)
          return PrimitiveEncoderInfinite.to_asn1(obj, definition)
        end

        type_new(value, type, tag, tagging)
      end
    end
  end
      
  class PrimitiveEncoderInfinite
    class << self
      include TypeEncoder, TemplateUtil
      
      def to_asn1(obj, definition)
        options = definition[:options]
        type = definition[:type] 
        tag = default_tag_of_type(type)
        tagging = options[:tagging]
        name = definition[:name]
        val = obj.instance_variable_get("@" + name.to_s)
        value = value_raise_or_default(val, name, options)
        return nil if value == nil
        
        case value
        when Array
          cons_value = Array.new
          value.each do |elem|
            cons_value << type.new(elem)
          end
          cons_value << OpenSSL::ASN1::EndOfContent.new
        else
          cons_value = [ type.new(value), OpenSSL::ASN1::EndOfContent.new ]  
        end
        
        type_new(cons_value, OpenSSL::ASN1::Constructive, tag, tagging, true)
      end
    end
  end
        
  class ConstructiveEncoder
    class << self
      include TypeEncoder, TemplateUtil
      
      def to_asn1(obj, definition, depth=0)
        options = definition[:options]
        type = definition[:type] 
        inner_def = definition[:inner_def]
        inf_length = obj.instance_variable_get(:@infinite_length)
        tag = options[:tag]
        tagging = options[:tagging]
        value = Array.new

        # if no inner values have been set, we can treat
        # the entire constructed value as not present
        if options[:optional]
          return nil if no_inner_vars_set?(inner_def, obj)
        end

        i = 0

        inner_def.each do |element|
          inner_obj, i = encode_inner(obj, element, i, depth)
          value << inner_obj if inner_obj
        end
        
        value << OpenSSL::ASN1::EndOfContent.new if inf_length
        
        type_new(value, type, tag, tagging, inf_length)
      end
      
      private
      
      def no_inner_vars_set?(inner_def, obj)
        one_set = false
        inner_def.each do |deff|
          iv = obj.instance_variable_get("@" + deff[:name].to_s)
          one_set = true unless iv == nil
        end
        !one_set
      end
      
      def encode_inner(obj, inner_def, index, depth)
        if inner_def[:encoder] == ConstructiveEncoder
          inner_obj = ConstructiveEncoder.to_asn1(obj, inner_def, depth + 1)
          index += 1
        else
          inner_obj = Encoder.to_asn1_obj(obj, inner_def)
        end
        
        unless inner_obj
          return nil, index 
        end
        
        inf_len_indices = obj.instance_variable_get(:@infinite_length_indices)
        indices = inf_len_indices ? inf_len_indices[depth] : nil
        if indices && indices[index]
          inner_obj.infinite_length = true
        end
        return inner_obj, index
      end
      
    end
  end
      
  class TemplateEncoder
    class << self
      include TypeEncoder, TemplateUtil
      
      def to_asn1(obj, definition)
        options = definition[:options]
        name = definition[:name]
        value = obj.instance_variable_get("@" + name.to_s)
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
        value = obj.instance_variable_get("@" + name.to_s)
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
        value = obj.instance_variable_get("@" + name.to_s)
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
        val = obj.instance_variable_get("@" + name.to_s)
        value = value_raise_or_default(val, name, options)
        return nil if value == nil
        unless value.is_a? ChoiceValue
          raise ArgumentError.new("ChoiceValue expected for #{name}")
        end

        tmp_def = get_definition(value, definition[:inner_def])
        tmp_def[:name] = :value
        if tmp_def[:encoder] == ConstructiveEncoder
          tmp_val = value.value #values to be encoded are in a helper object
        else
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

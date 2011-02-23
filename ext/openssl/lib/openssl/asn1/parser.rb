module OpenSSL::ASN1::Template
  #Every parser needs to match the ASN.1 object that is passed
  #to it. If it matches the expected value, the Encoder must set
  #the parsed value as an instance variable(@ + name.to_s). If
  #successful, the Encoder shall return true, false if it cannot
  #match the asn1 object. If it cannot match the asn1 object but
  #a default exists, then this default must may be set as an instance
  #variable (it should have already been set when initializing the
  #object), but the parse method shall return false.
  
  module TypeParser
    def check_size_cons(size, definition, inf_length)
      max_size = definition[:inner_def].size
      max_size += 1 if inf_length
      
      if size > max_size || size < definition[:min_size]
        raise OpenSSL::ASN1::ASN1Error.new(
          "Expected #{min_size}..#{max_size} values. Got #{size}")
      end
    end
            
    def unpack_tagged(asn1, type, tagging)
      return asn1 unless tagging && type
      case tagging
      when :EXPLICIT
        unpack_explicit(asn1)
      when :IMPLICIT
        unpack_implicit(asn1, type)
      else
        raise ArgumentError.new("Unrecognized tagging: #{tagging}")
      end
    end
          
    def unpack_explicit(asn1)
      unless asn1.value.size == 1
        unless asn1.value.size == 2 && asn1.value[1].tag == OpenSSL::ASN1::EOC
          raise OpenSSL::ASN1::ASN1Error.new(
            "Explicitly tagged value with multiple inner values")
        end    
      end
      asn1.value.first
    end
         
    def unpack_implicit(asn1, type)
      real_tag = default_tag_of_type(type)
      #implicitly tagged constructed values already contain
      #an array value; no need to en- and decode them as for 
      #primitive values
      tmp_asn1 =  OpenSSL::ASN1::ASN1Data.new(asn1.value, real_tag, :UNIVERSAL)
      unless real_tag == OpenSSL::ASN1::SEQUENCE ||
             real_tag == OpenSSL::ASN1::SET
        OpenSSL::ASN1.decode(tmp_asn1.to_der)
      else
        tmp_asn1
      end
    end
          
    def match(asn1, type, name, options, force_optional=false)
      tag = tag(options)
      if asn1.tag == tag_or_default(tag, type)
        unless asn1.tag_class == determine_tag_class(tag)
          raise OpenSSL::ASN1::ASN1Error.new(
            "Tag class mismatch. Expected: #{determine_tag_class(tag)} " +
            "Got: #{asn1.tag_class}")
        end
        true
      else
        unless optional(options) || default(options) != nil || force_optional
          name = name || 'unnamed'
          raise OpenSSL::ASN1::ASN1Error.new(
            "Mandatory value #{name} could not be parsed. "+
            "Expected tag: #{tag_or_default(tag(options), type)} Got: #{asn1.tag}")
        end
        false
      end
    end
      
  end
  
  class PrimitiveParser
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition)
        if asn1.infinite_length
          return PrimitiveParserInfinite.parse(obj, asn1, definition)
        end
        unless match(asn1, definition[:type], definition[:name], definition[:options])
          return false
        end

        value = unpack_tagged(asn1, definition[:type], tagging(definition[:options])).value
        obj.instance_variable_set(definition[:name], value)
        true
      end
    end
  end
      
  class PrimitiveParserInfinite
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition)
        unless match(asn1, definition[:type], definition[:name], definition[:options])
          return false
        end
        wrapped_value = unpack_tagged(asn1, definition[:type], tagging(definition[:options]))
        value = wrapped_value.value
            
        unless value.respond_to?(:each)
          value = single_value(wrapped_value, definition[:type])
          obj.instance_variable_set(definition[:name], value)
          return true
        end
          
        obj.instance_variable_set(definition[:name], convert_to_definite(value, OpenSSL::ASN1::CLASS_TAG_MAP[definition[:type]]))
        true
      end
      
      private

      def single_value(wrapped_value, type)
        unless wrapped_value.tag == OpenSSL::ASN1::CLASS_TAG_MAP[type]
          raise OpenSSL::ASN1::ASN1Error.new("Tag mismatch for infinite length primitive " +
             "value. Expected: #{OpenSSL::ASN1::CLASS_TAG_MAP[type]} Got: #{wrapped_value.tag}")
        end
        wrapped_value.value.instance_variable_set(:@infinite_length, true)
        wrapped_value.value.instance_variable_set(:@definite_value, true)
        wrapped_value.value.instance_variable_set(:@infinite_length_sizes,
                                                  [wrapped_value.value.bytesize])
        wrapped_value.value
      end

      def convert_to_definite(ary, tag)
        ret = ''
        inf_length_sizes = Array.new
        ary.each do |part|
          break if part.tag == OpenSSL::ASN1::EOC
          unless part.tag == tag
            raise OpenSSL::ASN1::ASN1Error.new(
              "Tag mismatch for infinite length primitive " +
              "value. Expected: #{tag} Got: #{part.tag}")
          end
          ret << part.value
          inf_length_sizes << part.value.bytesize
        end
        ret.instance_variable_set(:@infinite_length, true)
        ret.instance_variable_set(:@infinite_length_sizes, inf_length_sizes)
        ret
      end
      
    end
  end
      
  class ConstructiveParser
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition)
        unless match(asn1, definition[:type], nil, definition[:options])
          return false
        end
        seq = unpack_tagged(asn1, definition[:type], tagging(definition[:options])).value
            
        i = 0

        check_size_cons(seq.size, definition, asn1.infinite_length)
            
        definition[:inner_def].each do |deff|
          if !seq[i]
            handle_missing(obj, deff)
          elsif deff[:parser].parse(obj, seq[i], deff)
            i += 1
          end
        end
              
        if asn1.infinite_length
          unless seq[i].tag == OpenSSL::ASN1::EOC
            raise OpenSSL::ASN1::ASN1Error.new(
              "Expected EOC. Got #{seq[i].tag}")
          end
          obj.instance_variable_set(:@infinite_length, true)
        end
              
        num_parsed = asn1.infinite_length ? i + 1 : i
        unless seq.size == num_parsed
          raise OpenSSL::ASN1::ASN1Error.new(
            "Structural mismatch of constructed value. " +
            "Parsed: #{num_parsed}  of #{seq.size} values")
        end
        true
      end
          
      private 
          
      def handle_missing(obj, deff)
        unless optional(deff[:options]) || default(deff[:options]) != nil
          raise OpenSSL::ASN1::ASN1Error.new(
            "Mandatory value #{deff[:name]} is missing.")
        end
      end
          
    end
  end
      
  class TemplateParser
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition)
        instance = definition[:type].parse(asn1, definition[:options], true)
        return false unless instance
        obj.instance_variable_set(definition[:name], instance) #TODO if setter ?
        true
      end
    end
  end

  class AnyParser
    class << self
      include TypeParser, TemplateUtil

      def parse(obj, asn1, definition)
        if optional(definition[:options])
          if tag(definition[:options])
            #won't raise, tag prevents trouble with type==nil
            unless match(asn1, nil, definition[:name], definition[:options])
              return false
            end
          else
            OpenSSL::ASN1::ASN1Error.new("Cannot unambiguously assign ASN.1 Any")
          end
        end

        asn1.instance_variable_set(:@parsed, true) #allows shortcut for re-encoding
        obj.instance_variable_set(definition[:name], asn1)
        true
      end
    end
  end
      
  class SequenceOfParser
    class << self
      
      def parse(obj, asn1, definition)
        ConstructiveOfParser.parse(obj, asn1, definition, OpenSSL::ASN1::Sequence)
      end
    end
  end
      
  class SetOfParser
    class << self
          
      def parse(obj, asn1, definition)
        ConstructiveOfParser.parse(obj, asn1, definition, OpenSSL::ASN1::Set)
      end
    end
  end
      
  class ConstructiveOfParser
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition, type)
        unless match(asn1, type, definition[:name], definition[:options])
          return false
        end

        seq = unpack_tagged(asn1, type, tagging(definition[:options])).value

        ret = definition[:type].respond_to?(:parse) ?
            parse_templates(seq, definition[:type]) :
            parse_primitives(seq)

        if asn1.infinite_length && seq[seq.size - 1].tag != OpenSSL::ASN1::EOC
          raise OpenSSL::ASN1::ASN1Error.new(
            "Expected EOC. Got #{seq[seq.size - 1].tag}")
        end
              
        obj.instance_variable_set(definition[:name], ret)
        true
      end

      private

      def parse_templates(seq, type)
        seq.map do |val|
          next if val.tag == OpenSSL::ASN1::EOC
          type.parse(val, nil, false) #raise if no match
        end
      end

      def parse_primitives(seq)
        seq.map do |val|
          val.value
        end
      end

    end
  end
      
  class ChoiceParser
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition)
        deff = match_inner_def(asn1, definition)
        return false unless deff

        deff[:name] = :@value
        choice_val = ChoiceValue.new(deff[:type], nil, tag(deff[:options]))
        deff[:parser].parse(choice_val, asn1, deff)
        obj.instance_variable_set(definition[:name], choice_val)
        true
      end
          
      private
          
      def match_inner_def(asn1, definition)
        first_any = -1
        i = 0

        definition[:inner_def].each do |deff|
          if deff[:type] == OpenSSL::ASN1::Any
            tag = tag(deff[:options])
            if tag && asn1.tag == tag
              return deff
            else
              first_any = i
            end
          else
            if match(asn1, real_type(deff[:type]), definition[:name], deff[:options], true)
              return deff
            end
          end
          i += 1
        end

        if first_any != -1
          return definition[:inner_def][first_any]
        end

        unless optional(definition[:options]) || default(definition[:options])
          raise OpenSSL::ASN1::ASN1Error.new(
            "Mandatory Choice value #{definition[:name]} not found.")
        end
        nil
      end
    end
  end
      
  class UTF8Parser
    class << self
      include TypeParser, TemplateUtil
        
      def parse(obj, asn1, definition)
        unless PrimitiveParser.parse(obj, asn1, definition)
          return false
        end
        obj.instance_variable_set(definition[:name],
          obj.instance_variable_get(definition[:name]).force_encoding('UTF-8'))
        true
      end
    end
  end

  class NullParser
    class << self
      include TypeParser, TemplateUtil

      def parse(obj, asn1, definition)
        unless match(asn1, definition[:type], definition[:name], definition[:options])
          return false
        end
        # shortcut - won't set value
        true
      end

    end
  end

  class ObjectIdParser
    class << self
      include TypeParser, TemplateUtil

      def parse(obj, asn1, definition)
        unless match(asn1, definition[:type], definition[:name], definition[:options])
          return false
        end
        # set the ASN1 object instead of only the value
        value = unpack_tagged(asn1, definition[:type], tagging(definition[:options]))
        value.instance_variable_set(:@parsed, true)
        obj.instance_variable_set(definition[:name], value)
        true
      end
    end
  end

end

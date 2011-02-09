module OpenSSL::ASN1::Template
  #Every parser needs to match the ASN.1 object that is passed
  #to it. If it matches the expected value, the Encoder must set
  #the parsed value as an instance variable(@ + name.to_s). If
  #successful, the Encoder shall return true, false if it cannot
  #match the asn1 object. If it cannot match the asn1 object but
  #a default exists, then this default must be set as an instance
  #variable, but the parse method shall return false.
  module Parser
    class << self
      def parse_recursive(obj, asn1, definition)
        definition[:parser].parse(obj, asn1, definition)
      end
    end
  end
  
  module TypeParser
    def check_size_cons(size, inner_def, inf_length)
      max_size = inner_def.size
      max_size += 1 if inf_length
      min_size = min_size(inner_def)
    
      if size > max_size || size < min_size
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
      unpacked = asn1.value
      unless unpacked.size == 1
        raise OpenSSL::ASN1::ASN1Error.new(
          "Explicitly tagged value with multiple inner values")
      end
      asn1.value.first
    end
         
    def unpack_implicit(asn1, type)
      real_tag = default_tag_of_type(type)
      #implicitly tagged constructed values already contain
      #an array value; no need to en- and decode them as for 
      #primitive values
      tmp_asn1 = OpenSSL::ASN1::ASN1Data.new(asn1.value, real_tag, :UNIVERSAL)
      unless real_tag == OpenSSL::ASN1::SEQUENCE ||
             real_tag == OpenSSL::ASN1::SET
        OpenSSL::ASN1.decode(tmp_asn1.to_der)
      else
        tmp_asn1
      end
    end
          
    def min_size(inner_def)
      min_size = 0
      inner_def.each do |definition|
        options = definition[:options]
        min_size += 1 unless options[:optional] || options[:default] != nil
      end
      min_size
    end
          
    def match(asn1, type, name, options)
      tag = options[:tag]
      real_tag = tag_or_default(tag, type)
      if asn1.tag == real_tag
        tag_class = determine_tag_class(tag)
        unless asn1.tag_class == tag_class
          raise OpenSSL::ASN1::ASN1Error.new(
            "Tag class mismatch. Expected: #{tag_class} " +
            "Got: #{asn1.tag_class}")
        end
        tmp_asn1 = unpack_tagged(asn1, type, options[:tagging])
        return tmp_asn1.value, true
      else
        default = options[:default]
        if default
          return default, false
        else
          unless options[:optional]
            name = name || 'unnamed'
            raise OpenSSL::ASN1::ASN1Error.new(
              "Mandatory value #{name} could not be parsed. "+
              "Expected tag: #{real_tag} Got: #{asn1.tag}")
          end
          return nil, false
        end
      end
    end
      
  end
  
  class PrimitiveParser
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition)
        type = definition[:type]
        setter = definition[:setter]
        options = definition[:options]
                        
        if asn1.infinite_length
          return PrimitiveParserInfinite.parse(obj, asn1, definition)
        end
          
        value, matched = match(asn1, type, setter, options)
        return false unless value || matched
            
        obj.send(setter, value) if definition[:name]
        matched
      end
    end
  end
      
  class PrimitiveParserInfinite
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition)
        type = definition[:type]
        setter = definition[:setter]
        options = definition[:options]
            
        val, matched = match(asn1, type, setter, options)
        return false unless val || matched
            
        unless val.respond_to?(:each)
          raise OpenSSL::ASN1::ASN1Error.new(
            "Value #{name} (#{val}) is not constructed although " +
            "expected to be of infinite length.")
        end
          
        tag = default_tag_of_class(type)
        value = Array.new
            
        val.each do |part|
          unless part.tag == OpenSSL::ASN1::EOC
            unless part.tag == tag
              raise OpenSSL::ASN1::ASN1Error.new(
                "Tag mismatch for infinite length primitive " +
                "value. Expected: #{tag} Got: #{part.tag}")
            end
            value << part.value 
          end
        end
            
        obj.send(setter, value)
        matched
      end
    end
  end
      
  class ConstructiveParser
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition)
        options = definition[:options]
        inner_def = definition[:inner_def]
        type = definition[:type]
        inf_length = asn1.infinite_length
            
        seq, matched = match(asn1, type, nil, options)
        return false unless seq # || matched not needed, value != false
            
        i = 0
        actual_size = seq.size
            
        check_size_cons(actual_size, inner_def, inf_length)
            
        inner_def.each do |deff|
          inner_asn1 = seq[i]
          if !inner_asn1
            handle_missing(obj, deff)
          elsif Parser.parse_recursive(obj, inner_asn1, deff)
            i += 1
          end
        end
              
        if inf_length
          unless seq[i].tag == OpenSSL::ASN1::EOC
            raise OpenSSL::ASN1::ASN1Error.new(
              "Expected EOC. Got #{seq[i].tag}")
          end
          obj.instance_variable_set(:@infinite_length, true)
        end
              
        num_parsed = inf_length ? i + 1 : i
            
        unless actual_size == num_parsed
          raise OpenSSL::ASN1::ASN1Error.new(
            "Structural mismatch of constructed value. " +
            "Parsed: #{num_parsed}  of #{actual_size} values")
        end
        matched
      end
          
      private 
          
      def handle_missing(obj, deff)
        options = deff[:options]
        setter = deff[:setter]
        default = options[:default]
        unless options[:optional] || default != nil
          raise OpenSSL::ASN1::ASN1Error.new(
            "Mandatory value #{deff[:name]} is missing.")
        end
        if default && name
            obj.send(setter, default)
        end
      end
          
    end
  end
      
  class TemplateParser
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition)
        setter = definition[:setter]
            
        instance = definition[:type].parse(asn1, definition[:options], true)
        return false unless instance
            
        obj.send(setter, instance) #TODO if setter ?
        true
      end
    end
  end

  class AnyParser
    class << self
      include TypeParser, TemplateUtil

      def parse(obj, asn1, definition)
        setter = definition[:setter]
        options = definition[:options]
            
        if options[:optional]
          if (options[:tag])
            #won't raise, tag prevents trouble with type==nil
            value, matched = match(asn1, nil, setter, options)
            return false unless value
          else
            OpenSSL::ASN1::ASN1Error.new("Cannot unambiguously assign ASN.1 Any")
          end
        end
        
        obj.send(setter, asn1)
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
        options = definition[:options]
        inner_type = definition[:type]
        is_template = inner_type.include? OpenSSL::ASN1::Template
        setter = definition[:setter]
        inf_length = asn1.infinite_length
                        
        seq, matched = match(asn1, type, setter, options)
        return false unless seq
            
        unless is_template || matched
          seq = wrap_defaults(inner_type, seq)
        end
            
        ret = Array.new
        if is_template
          tmp_class = Class.new do
            attr_accessor :object
          end
          tmp = tmp_class.new
          deff = { type: inner_type, name: :object, setter: :object=, options: {} }
        end
            
        seq.each do |val|
          next if val.tag == OpenSSL::ASN1::EOC
              
          if is_template
            consumed = TemplateParser.parse(tmp, val, deff)
            ret << tmp.object if consumed
            unless consumed
              raise OpenSSL::ASN1::ASN1.Error.new("Type mismatch in " +
                " constructive sequence of. Expected #{inner_type}.Got: #{val}")
            end
          else
            ret << val.value
          end
        end
              
        if inf_length && seq[seq.size - 1].tag != OpenSSL::ASN1::EOC
          raise OpenSSL::ASN1::ASN1Error.new(
            "Expected EOC. Got #{seq[i].tag}")
        end
              
        obj.send(setter, ret)
        matched
      end
          
      private
          
      def wrap_defaults(inner_type, defaults)
        ret = Array.new
        defaults.each do |val|
          ret << inner_type.new(val)
        end
        ret
      end
                        
    end
  end
      
  class ChoiceParser
    class << self
      include TypeParser, TemplateUtil
          
      def parse(obj, asn1, definition)
        options = definition[:options]
        setter = definition[:setter]
        
        deff = match_inner_def(asn1, definition)
        unless deff
          default = options[:default]
          if default
            obj.send(setter, default)
          end
          return false
        end
            
        return true unless name

        deff[:name] = :value
        deff[:setter] = :value=
        type = deff[:type]
        choice_val = ChoiceValue.new(type, nil, deff[:options][:tag])
        
        if deff[:parser] == ConstructiveParser
          container = create_object(deff[:inner_def])
          ConstructiveParser.parse(container, asn1, deff)
          choice_val.value = container
        else
          deff[:parser].parse(choice_val, asn1, deff)
        end

        obj.send(setter, choice_val)
        true
      end
          
      private
          
      def match_inner_def(asn1, definition)
        setter = definition[:setter]
        inner_def = definition[:inner_def]
        outer_opts = definition[:options]
        default = outer_opts[:default]
        any_defs = Array.new
        
        inner_def.each do |deff|
          options = deff[:options].merge({ optional: true })
          if deff[:type] == OpenSSL::ASN1::ASN1Data #asn1_any
            any_defs << deff
            next
          else
            value, matched = match(asn1, deff[:type], setter, options)
            return deff if matched
          end
        end
            
        #any fallback
        unless any_defs.empty?
          any_defs.each do |any_def|  
            tag = any_def[:options][:tag]
            if tag
              return any_def if asn1.tag == tag
            else
              return any_def
            end
          end
        end
          
        unless outer_opts[:optional] || default
          raise OpenSSL::ASN1::ASN1Error.new(
            "Mandatory Choice value #{setter} not found.")
        end
        nil
      end
          
      def create_object(inner_def)
        members = Array.new            
        inner_def.each do |deff|
          name = deff[:name]
          members << name if name
        end
        tmp_class = Class.new do
          members.each do |member|
            attr_accessor member
          end
        end
        tmp_class.new
      end
      
    end
  end
      
  class UTF8Parser
    class << self
      include TypeParser, TemplateUtil
        
      def parse(obj, asn1, definition)
        setter = definition[:setter]
        tmp_class = Class.new do
          attr_accessor :object
        end
        tmp = tmp_class.new
        deff = { type: definition[:type], name: :object, setter: :object=, options: definition[:options] }
        ret = PrimitiveParser.parse(tmp, asn1, deff)
        return false unless ret
        utf8 = tmp.object.force_encoding('UTF-8')
        obj.send(setter, utf8)
        true
      end
    end
  end

end

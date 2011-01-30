=begin
= $RCSfile$ -- A DSL that allows to easily define ASN.1 structures that
               automatically provide a +parse+ and +to_der+ method

= Info
  Copyright (C) 2011  Martin Bosslet <Martin.Bosslet@googlemail.com>
  All rights reserved.

= Licence
  This program is licenced under the same licence as Ruby.
  (See the file 'LICENCE'.)

= Version
  $Id: asn1_template.rb $
=end

module OpenSSL
  module ASN1
    #Provides class methods that define the underlying ASN.1 structure of 
    #a class. Defining the structure in this manner also automatically adds
    #parsing and encoding facilities by adding a +to_der+ method to the
    #class instance and by providing a +parse+ class method in the class that
    #includes this module.
    #available options { optional: false, tag: nil, 
    #                    tagging: nil, infinite_length: false,
    #                    tag_class: nil, default: nil }
    #definition {type, name, inner_def, options, parser, encoder}
    module Template
      
      def self.included(base)
        base.extend TemplateMethods
        tmp_self = self
        base.define_singleton_method :parse do |asn1, options={}|
          definition = @_definition.merge({ options: options })
          
          unless asn1 || options[:optional]
            raise OpenSSL::ASN1::ASN1Error.new(
            "Mandatory parameter not set. Type: #{definition[:type]} " +
            " Name: #{definition[:name]}")
          end
            
          return nil unless asn1
          
          unless asn1.respond_to?(:to_der)
            asn1 = OpenSSL::ASN1.decode(asn1)
            obj = base.new
          else
            obj = base.new(options)  
          end
          
          Parser.parse_recursive(obj, asn1, definition)
          obj
        end
      end
      
      def initialize(options={})
        unless options.is_a?(Hash)
          parse_raw(options)
        else
          @options = options
          definition = self.class.instance_variable_get(:@_definition).merge({ options: options })
          init_mandatory_templates(definition)
        end
      end
      
      def to_der
        asn1_obj = to_asn1
        asn1_obj ? asn1_obj.to_der : nil
      end

      def to_asn1
        definition = self.class.instance_variable_get(:@_definition).merge({ options: @options })
        Encoder.to_asn1_obj(self, definition)
      end
      
      private
      
      def parse_raw(raw)
        asn1 = OpenSSL::ASN1.decode(raw)
        definition = self.class.instance_variable_get(:@_definition)
        Parser.parse_recursive(self, asn1, definition)
      end
      
      def init_mandatory_templates(definition)
        inner_def = definition[:inner_def]
        
        if inner_def
          inner_def.each do |deff|
            init_mandatory_templates(deff)
          end
        else
          type = definition[:type]
          options = definition[:options]
          if type && type.include?(Template) && !options[:optional]
            instance = type.new(options)
            instance_variable_set("@" + definition[:name].to_s, instance)
          end
        end
      end
      
      module TemplateUtil
        
        def determine_tag_class(tag, tag_class)
          return tag_class if tag_class
          
          if tag
            :CONTEXT_SPECIFIC
          else
            :UNIVERSAL
          end
        end
        
        def real_type(type)
          unless type.include? Template
            type
          else
            type.instance_variable_get(:@_definition)[:type]
          end
        end
        
        def tag_or_default(tag, type)
          if tag
            tag
          else
            tmp_type = real_type(type)
            default_tag_of_class(tmp_type)
          end
        end
        
        def default_tag_of_class(klass)
          val = OpenSSL::ASN1::CLASS_TAG_MAP[klass]
          unless val
            raise OpenSSL::ASN1::ASN1Error.new(
              "Universal tag for #{klass} not found")
          end
          val
        end
        
        def default_tag_of_type(type)
          tmp_type = real_type(type)
          default_tag_of_class(tmp_type)
        end
        
      end
      
      module TypeEncoder 
        
        def type_new(value, type, tag, tagging, tag_class, inf_length=nil)
          unless tag
            val = type.new(value)
            val.infinite_length = true if inf_length
            val
          else
            tmp_tc = unless tag_class
              :CONTEXT_SPECIFIC
            else
              tag_class
            end
            encode_explicit(value, type, tag, tagging, tmp_tc, inf_length)
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
            if options[:infinite_length]
              return PrimitiveEncoderInfinite.to_asn1(obj, definition)
            end
            
            type = definition[:type] 
            tag = options[:tag]
            tagging = options[:tagging]
            tag_class = options[:tag_class]
            name = definition[:name]
            val = obj.instance_variable_get("@" + name.to_s)
            
            if type == OpenSSL::ASN1::Null
              return nil if options[:optional]
              return type_new(nil, type, tag, tagging, tag_class)
            end
            
            value = value_raise_or_default(val, name, options) 
            return nil if value == nil
            type_new(value, type, tag, tagging, tag_class)
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
            tag_class = determine_tag_class(tag, options[:tag_class])
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
            
            type_new(cons_value, OpenSSL::ASN1::Constructive, tag, tagging, tag_class, true)
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
            inf_length = options[:infinite_length]
            tag = options[:tag]
            tagging = options[:tagging]
            tag_class = options[:tag_class]
            value = Array.new
            
            inner_def.each do |element|
              inner_obj = Encoder.to_asn1_obj(obj, element)
              value << inner_obj if inner_obj
            end
              
            # if no inner values have been set, we can treat 
            # the entire constructed value as not present
            return nil if value.empty?
              
            value << OpenSSL::ASN1::EndOfContent.new if inf_length
              
            type_new(value, type, tag, tagging, tag_class, inf_length)
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
            value_raise_or_default(value, name, options)
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
            tagging = options[:tagging]
            tag_class = determine_tag_class(tag, options[:tag_class])
            name = definition[:name]
            inf_length = options[:infinite_length]
            value = obj.instance_variable_get("@" + name.to_s)
            value = value_raise_or_default(value, name, options)
            tag = tag || value.tag
            unless tagging 
              if value.respond_to?(:tagging)
                tagging = value.tagging
              end
            end
            return nil if value == nil
            encode_explicit(value, tag, tagging, tag_class, inf_length)
          end
          
          private
          
          def encode_explicit(value, tag, tagging, tag_class, inf_length)
            #Changing value here should be fine, it's only related to this instance,
            #not the global definition
            if tagging == :EXPLICIT
              #try to make inner untagged
              value.tag = default_tag(value)
              if value.respond_to?(:tagging)
                value.tagging = nil
              end
              value.tag_class = :UNIVERSAL
              outer = OpenSSL::ASN1Data.new([value], tag, tag_class)
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
            end
            
            raise OpenSSL::ASN1::ASN1Error("No universal tag found for class #{value.class}")
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
            tag_class = options[:tag_class]
            inf_length = options[:infinite_length]
            value = obj.instance_variable_get("@" + name.to_s)
            value_raise_or_default(value, name, options)
            return nil if value == nil
            seq_value = Array.new
            value.each do |element|
              #inner values are either template types or primitives
              elem_value = element.respond_to?(:to_asn1) ? 
                           element.to_asn1 : inner_type.new(element)
              seq_value << elem_value
            end
            type_new(seq_value, type, tag, tagging, tag_class, inf_length)
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
            type = value.type
            
            tmp_def = get_definition(value, definition[:inner_def])
            tmp_def[:name] = :value
            tmp_def[:options][:infinite_length] = options[:infinite_length]
            if value.type.include? Template
              TemplateEncoder.to_asn1(value, tmp_def)
            elsif value.type.superclass == OpenSSL::ASN1::Primitive
              PrimitiveEncoder.to_asn1(value, tmp_def)
            elsif value.type.superclass == OpenSSL::ASN1::Constructive
              ConstructiveEncoder.to_asn1(value.value, tmp_def)
            elsif value.type == OpenSSL::ASN1::ASN1Data
              AnyEncoder.to_asn1(value, tmp_def)
            else
              raise ArgumentError.new("Unsupported ChoiceValue type #{value.type}")
            end
          end
          
          private
          
          def get_definition(choice_val, inner_def)
            inner_def.each do |deff|
              if choice_val.type == deff[:type] && 
                 choice_val.tag == deff[:options][:tag]
                return deff.merge({})
              end
            end
            raise OpenSSL::ASN1::ASN1Error.new("Found no definition for "+
                  "#{choice_val.type} in Choice")
          end
        end
      end
      
      #Every encoder needs to construct a subtype of 
      #OpenSSL::ASN1::ASN1Data from the definition that
      #is passed, and possible the instance variable
      #that can be retrieved from definition[:name]
      #Tags, tagging, tag_class and infinite_length
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
            min_size += 1 unless definition[:options][:optional]
          end
          min_size
        end
          
        def match(asn1, type, name, options)
          tag = options[:tag]
          real_tag = tag_or_default(tag, type)
          if asn1.tag == real_tag
            tag_class = determine_tag_class(tag, options[:tag_class])
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
            name = definition[:name] 
            options = definition[:options]
                        
            if definition[:infinite_length] || asn1.infinite_length
              return PrimitiveParserInfinite.parse(obj, asn1, definition)
            end
            
            value, matched = match(asn1, type, name, options)
            return false unless value || matched
            
            if name
              obj.instance_variable_set("@" + name.to_s, value)
            end
            matched
          end
        end
      end
      
      class PrimitiveParserInfinite
        class << self
          include TypeParser, TemplateUtil
          
          def parse(obj, asn1, definition)
            type = definition[:type]
            name = definition[:name] 
            options = definition[:options]
            
            value, matched = match(asn1, type, name, options)
            return false unless value || matched
            
            unless ary.respond_to?(:each)
              raise OpenSSL::ASN1::ASN1Error.new(
                "Value #{name} (#{ary}) is not constructed although " +
                "expected to be of infinite length.")
            end
            
            tag = default_tag_of_class(type)
            value = Array.new
            
            asn1.each do |part|
              unless part.tag == OpenSSL::ASN1::EOC
                unless part.tag == tag
                  raise OpenSSL::ASN1::ASN1Error.new(
                    "Tag mismatch for infinite length primitive " +
                    "value. Expected: #{tag} Got: #{part.tag}")
                end
                value << part.value 
              end
            end
            
            if name
              obj.instance_variable_set("@" + name.to_s, value)
            end
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
            optional = options[:optional]
            tagging = options[:tagging]
            inf_length = options[:infinite_length]
            
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
              
            if inf_length && seq[i].tag != OpenSSL::ASN1::EOC
              raise OpenSSL::ASN1::ASN1Error.new(
                "Expected EOC. Got #{seq[i].tag}")
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
            name = deff[:name]
            default = options[:default]
            unless options[:optional] || default != nil
              raise OpenSSL::ASN1::ASN1Error.new(
                "Mandatory value #{deff[:name]} is missing.")
            end
            if default && name
                obj.instance_variable_set("@" + name.to_s, default)
            end
          end
          
        end
      end
      
      class TemplateParser
        class << self
          include TypeParser, TemplateUtil
          
          def parse(obj, asn1, definition)
            name = definition[:name]
            instance = definition[:type].parse(asn1, definition[:options])
            if name
              obj.instance_variable_set("@" + name.to_s, instance)
            end
            true
          end
        end
      end

      class AnyParser
        class << self
          include TypeParser, TemplateUtil

          def parse(obj, asn1, definition)
            name = definition[:name]
            options = definition[:options]
            
            if options[:optional]
              if (options[:tag])
                #won't raise, tag prevents trouble with type==nil
                value, matched = match(asn1, nil, name, options)
                return false unless value
              else
                OpenSSL::ASN1::ASN1Error.new("
                  Cannot unambiguously assign ASN.1 Any")
              end
            end
            
            if name
              obj.instance_variable_set("@" + name.to_s, asn1)
            end
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
            is_template = inner_type.include? Template
            name = definition[:name]
            optional = options[:optional]
            tagging = options[:tagging]
            inf_length = options[:infinite_length]
                        
            seq, matched = match(asn1, type, name, options)
            return false unless seq
            
            ret = Array.new
            if is_template
              tmp_class = Class.new do
                attr_accessor :object
              end
              tmp = tmp_class.new
              deff = { type: inner_type, name: :object, options: {} }
            end
            
            seq.each do |val|
              next if val.tag == OpenSSL::ASN1::EOC
              
              if is_template
                TemplateParser.parse(tmp, val, deff)
                ret << tmp.object
              else
                ret << val.value
              end
            end
              
            if inf_length && seq[seq.size - 1].tag != OpenSSL::ASN1::EOC
              raise OpenSSL::ASN1::ASN1Error.new(
                "Expected EOC. Got #{seq[i].tag}")
            end
              
            if name
              obj.instance_variable_set("@" + name.to_s, ret)
            end
            matched
          end
        end
      end
      
      class ChoiceParser
        class << self
          include TypeParser, TemplateUtil
          
          def parse(obj, asn1, definition)
            options = definition[:options]
            name = definition[:name]
            
            deff = match_inner_def(asn1, definition)
            unless deff
              default = options[:default]
              if name && default
                obj.instance_variable_set("@" + name.to_s, default)
              end
              return false
            end
            
            return true unless name
              
            deff[:name] = :value
            type = deff[:type]
            choice_val = ChoiceValue.new(type, nil, deff[:options][:tag])
            if type.include? Template
              TemplateParser.parse(choice_val, asn1, deff)
            elsif choice_val.type.superclass == OpenSSL::ASN1::Primitive
              PrimitiveParser.parse(choice_val, asn1, deff)
            elsif choice_val.type.superclass == OpenSSL::ASN1::Constructive
              container = create_object(deff[:inner_def])
              ConstructiveParser.parse(container, asn1, deff)
              choice_val.value = container
            elsif choice_val.type == OpenSSL::ASN1::ASN1Data
              AnyParser.parse(choice_val, asn1, deff)
            else
              raise ArgumentError.new("Unsupported ChoiceValue type #{value.type}")
            end
            obj.instance_variable_set("@" + name.to_s, choice_val)
            true
          end
          
          private
          
          def match_inner_def(asn1, definition)
            name = definition[:name]
            inner_def = definition[:inner_def]
            outer_opts = definition[:options]
            default = outer_opts[:default]
                        
            inner_def.each do |deff|
              options = deff[:options].merge({ optional: true })
              value, matched = match(asn1, deff[:type], name, options)
              return deff if matched
            end
            
            unless outer_opts[:optional] || default
              raise OpenSSL::ASN1::ASN1Error.new(
                "Mandatory Choice value #{name} not found.")
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
            name = definition[:name]
            tmp_class = Class.new do
              attr_accessor :object
            end
            tmp = tmp_class.new
            deff = { type: definition[:type], name: :object, options: definition[:options] }
            ret = PrimitiveParser.parse(tmp, asn1, deff)
            return false unless ret
            return ret unless name
            utf8 = tmp.object.force_encoding('UTF-8')
            obj.instance_variable_set("@" + name.to_s, utf8)
            true
          end
        end
      end
      
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
            
      module TemplateMethods
        
        def asn1_declare(type)
          @_definition = { type: type, 
                           options: {}, 
                           inner_def: Array.new, 
                           encoder: ConstructiveEncoder,
                           parser: ConstructiveParser }
          cur_def = @_definition
                    
          eigenclass = class << self; self; end
          eigenclass.instance_eval do
            
            define_method :declare_prim do |meth_name, type|
              eigenclass.instance_eval do
                define_method meth_name do |name=nil, opts={}|
                  attr_accessor name if name
                  
                  if type == OpenSSL::ASN1::UTF8String
                    parser = UTF8Parser
                  else
                    parser = PrimitiveParser
                  end
                  
                  deff = { type: type, 
                           name: name, 
                           options: opts, 
                           encoder: PrimitiveEncoder,
                           parser: parser }
                  cur_def[:inner_def] << deff
                end
              end
            end
            
            define_method :declare_cons do |meth_name, type|
              if !block_given?
                raise ArgumentError("#{meth_name} must be given a block.")
              end
              
              eigenclass.instance_eval do
                define_method meth_name do |opts={}, &proc|
                  tmp_def = cur_def
                  cur_def = { type: type,
                              options: opts, 
                              inner_def: Array.new, 
                              encoder: ConstructiveEncoder,
                              parser: ConstructiveParser }
                  proc.call
                  tmp_def[:inner_def] << cur_def
                  cur_def = tmp_def
                end
              end
            end
            
            define_method :declare_special_typed do |meth_name, encoder, parser|
              eigenclass.instance_eval do
                define_method meth_name do |type, name=nil, opts={}|
                  attr_accessor name if name
                  deff = { type: type,
                           name: name,
                           options: opts,
                           encoder: encoder,
                           parser: parser }
                  cur_def[:inner_def] << deff
                end
              end
            end
            
            define_method :asn1_any do |name=nil, opts={}|
              attr_accessor name if name
              deff = { name: name, 
                       options: opts, 
                       encoder: AnyEncoder,
                       parser: AnyParser }
              cur_def[:inner_def] << deff
            end
            
            define_method :asn1_choice do |name, opts={}, &proc|
              attr_accessor name
              tmp_def = cur_def
              cur_def = { name: name,
                          options: opts,
                          inner_def: Array.new,
                          encoder: ChoiceEncoder,
                          parser: ChoiceParser }
              proc.call
              tmp_def[:inner_def] << cur_def
              cur_def = tmp_def
            end
              
          end
          
          declare_prim(:asn1_boolean, OpenSSL::ASN1::Boolean)
          declare_prim(:asn1_integer, OpenSSL::ASN1::Integer)
          declare_prim(:asn1_bit_string, OpenSSL::ASN1::BitString)
          declare_prim(:asn1_octet_string, OpenSSL::ASN1::OctetString)
          declare_prim(:asn1_null, OpenSSL::ASN1::Null)
          declare_prim(:asn1_object_id, OpenSSL::ASN1::ObjectId)
          declare_prim(:asn1_enumerated, OpenSSL::ASN1::Enumerated)
          declare_prim(:asn1_utf8_string, OpenSSL::ASN1::UTF8String)
          declare_prim(:asn1_numeric_string, OpenSSL::ASN1::NumericString)
          declare_prim(:asn1_printable_string, OpenSSL::ASN1::PrintableString)
          declare_prim(:asn1_t61_string, OpenSSL::ASN1::T61String)
          declare_prim(:asn1_videotex_string, OpenSSL::ASN1::VideotexString)
          declare_prim(:asn1_ia5_string, OpenSSL::ASN1::IA5String)
          declare_prim(:asn1_utc_time, OpenSSL::ASN1::UTCTime)
          declare_prim(:asn1_generalized_time, OpenSSL::ASN1::GeneralizedTime)
          declare_prim(:asn1_graphic_string, OpenSSL::ASN1::GraphicString)
          declare_prim(:asn1_iso64_string, OpenSSL::ASN1::ISO64String)
          declare_prim(:asn1_general_string, OpenSSL::ASN1::GeneralString)
          declare_prim(:asn1_universal_string, OpenSSL::ASN1::UniversalString)
          declare_prim(:asn1_bmp_string, OpenSSL::ASN1::BMPString)
          
          declare_cons(:asn1_sequence, OpenSSL::ASN1::Sequence)
          declare_cons(:asn1_set, OpenSSL::ASN1::Set)
          
          declare_special_typed(:asn1_template, TemplateEncoder, TemplateParser)
          declare_special_typed(:asn1_sequence_of, SequenceOfEncoder, SequenceOfParser)
          declare_special_typed(:asn1_set_of, SetOfEncoder, SetOfParser)
          
          yield
        end
        
      end
      
      class ChoiceValue
        attr_accessor :type
        attr_accessor :tag
        attr_accessor :value
          
        def initialize(type, value = nil, tag=nil)
          @type = type
          @value = value
          @tag = tag
        end
      end
    end
  end
end

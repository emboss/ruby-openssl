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
require "openssl"
require "pp"

module OpenSSL
  module ASN1
    #Provides class methods that define the underlying ASN.1 structure of 
    #a class. Defining the structure in this manner also automatically adds
    #parsing and encoding facilities by adding a +to_der+ method to the
    #class instance and by providing a +parse+ class method in the class that
    #includes this module.
    
    #TODO: test for default_tag and default_tag_class
    #TODO: Readme: copy files under lib, too.
    #TODO: sequence_of, set_of, choice
    #TODO: asn1_any
    #TODO: convert infinite length primitives to a single primitive if not expected from definition
    
    #available options { optional: false, tag: nil, 
        #                tagging: nil, infinite_length: false,
        #                tag_class: nil, default: nil,
        #                parse_ignore: false }
        #definition {type, name, inner_def, options, parser, encoder}
    module Template
      
      def self.included(base)
        base.extend TemplateMethods
        tmp_self = self
        base.define_singleton_method :parse do |asn1, options={}|
          definition = @_definition
          definition[:options] = options
          
          unless asn1 || options[:optional]
            raise OpenSSL::ASN1::ASN1Error.new(
            "Mandatory parameter not set. Type: #{definition[:type]} " +
            " Name: #{definition[:name]}")
          end
            
          return nil unless asn1
          
          obj = base.new(options)
          Parser.parse_recursive(obj, asn1, definition)
          obj
        end
      end
      
      def initialize(options={})
        @_options = options
        definition = self.class.instance_variable_get(:@_definition)
        definition[:options] = options
        init_mandatory_templates(definition)
      end
      
      def to_der
        asn1_obj = to_asn1
        asn1_obj ? asn1_obj.to_der : nil
      end

      def to_asn1
        definition = self.class.instance_variable_get(:@_definition)
        Encoder.to_asn1_obj(self, definition)
      end
      
      private
      
      def init_mandatory_templates(definition)
        inner_def = definition[:inner_def]
        
        if inner_def
          inner_def.each do |deff|
            init_mandatory_templates(deff)
          end
        else
          type = definition[:type]
          options = definition[:options]
          if type.include?(Template) && !options[:optional]
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
            type._definition[:type]
          end
        end
        
        def tag_or_default(tag, type)
          if tag
            tag
          else
            tmp_type = real_type(type)
            OpenSSL::ASN1.default_tag_of_class(tmp_type)
          end
        end
        
        def default_tag_of_type(type)
          tmp_type = real_type(type)
          OpenSSL::ASN1.default_tag_of_class(tmp_type)
        end
        
      end
      
      module TypeEncoder 
        
        def type_new(value, type, tag, tagging, tag_class)
          unless tag
            type.new(value)
          else
            type.new(value, tag, tagging, tag_class)
          end
        end
        
        def value_raise_or_default(value, name, options)
          optional = options[:optional]
          default = options[:default]
                    
          unless value
            unless optional || default
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
            tag_class = determine_tag_class(tag, options[:tag_class])
            name = definition[:name]
            val = obj.instance_variable_get("@" + name.to_s)
            value = value_raise_or_default(val, name, options)
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
              
            cons = OpenSSL::ASN1::Constructive.new(cons_value, 
                                                   tag,
                                                   tagging,
                                                   tag_class)
            cons.infinite_length = true
            cons
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
            tag_class = determine_tag_class(tag, options[:tag_class])
            value = Array.new
              
            inner_def.each do |element|
              inner_obj = Encoder.to_asn1_obj(obj, element)
              value << inner_obj if inner_obj
            end
              
            # if no inner values have been set, we can treat 
            # the entire constructed value as not present
            return nil if value.empty?
              
            value << OpenSSL::ASN1::EndOfContent.new if inf_length
              
            constructed = type_new(value, type, tag, tagging, tag_class)
            constructed.infinite_length = inf_length
            constructed
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
            value.instance_variable_set(:@_options, options)
            value.to_asn1
          end
        end
      end
      
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
          return asn1 unless (tagging && asn1) 
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
          asn1.tag = real_tag
          asn1.tag_class = :UNIVERSAL
          unless real_tag == OpenSSL::ASN1::SEQUENCE ||
                 real_tag == OpenSSL::ASN1::SET
            OpenSSL::ASN1.decode(asn1.to_der)
          else
            asn1
          end
        end
          
        def min_size(inner_def)
          min_size = 0
          inner_def.each do |definition|
            min_size += 1 unless definition[:options][:optional]
          end
          min_size
        end
          
        def match(asn1, type, tag)
          return false unless asn1
           
          real_tag = tag_or_default(tag, type)
            
          if asn1.tag == real_tag
            true
          else
            false
          end
        end
          
        def check_asn1(asn1, type, options)
          check_mandatory(asn1, name, options[:optional])
          
          tag = options[:tag]
          real_tag = tag_or_default(tag, type)
          tag_class = determine_tag_class(tag, options[:tag_class])
           
          unless asn1.tag == real_tag
            raise OpenSSL::ASN1::ASN1Error.new(
              "Tagging mismatch. Expected: #{tag} Got: #{asn1.tag}")
          end
           
          unless asn1.tag_class == tag_class
            raise OpenSSL::ASN1::ASN1Error.new(
              "Tag class mismatch. Expected: #{tag_class} " +
              "Got: #{asn1.tag_class}")
          end
        end
        
        def check_mandatory(asn1, name, optional)
          unless asn1 || optional
            raise OpenSSL::ASN1::ASN1Error.new(
                "Mandatory value #{name} not set.")
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
            ignore = options[:parse_ignore]
            
            if definition[:infinite_length] || asn1.infinite_length
              return PrimitiveParserInfinite.parse(obj, asn1, definition)
            end
            
            check_asn1(asn1, type, options)
            asn1 = unpack_tagged(asn1, type, options[:tagging])
            value = asn1.value
            unless ignore
              obj.instance_variable_set("@" + name.to_s, asn1.value)
            end
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
            ignore = options[:parse_ignore]
            
            check_asn1(asn1, type, options)
            asn1 = unpack_tagged(asn1, type, options[:tagging])
            ary = asn1.value
            
            unless ary.respond_to?(:each)
              raise OpenSSL::ASN1::ASN1Error.new(
                "Value #{name} (#{ary}) is not constructed although " +
                "expected to be of infinite length.")
            end
            
            tag = OpenSSL::ASN1.default_tag_of_class(type)
            value = Array.new
            
            asn1.each do |part|
              unless part.tag == OpenSSL::ASN1::END_OF_CONTENT
                unless part.tag == tag
                  raise OpenSSL::ASN1::ASN1Error.new(
                    "Tag mismatch for infinite length primitive " +
                    "value. Expected: #{tag} Got: #{part.tag}")
                  end
                value << part.value 
              end
            end
            
            unless ignore
              obj.instance_variable_set("@" + name.to_s, value)
            end
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
            
            check_asn1(asn1, type, options)
            asn1 = unpack_tagged(asn1, type, tagging)
            i = 0
            seq = asn1.value
            actual_size = seq.size
            
            check_size_cons(actual_size, inner_def, inf_length)
            
            inner_def.each do |deff|
              inner_asn1 = seq[i]
              
              if match(inner_asn1, deff[:type], deff[:options][:tag])
                Parser.parse_recursive(obj, inner_asn1, deff)
                i += 1
              else
                unless deff[:options][:optional]
                  default = options[:default]
                  return default if default
                  raise OpenSSL::ASN1::ASN1Error.new(
                    "Mandatory parameter not set. Type: #{deff[:type]} " +
                    " Name: #{deff[:name]}")
                end
              end
            end
              
            if inf_length && seq[i].tag != OpenSSL::ASN1::END_OF_CONTENT
              raise OpenSSL::ASN1::ASN1Error.new(
                "Expected END_OF_CONTENT. Got #{seq[i].tag}")
            end
              
            num_parsed = inf_length ? i + 1 : i
            
            unless actual_size == num_parsed
              raise OpenSSL::ASN1::ASN1Error.new(
                "Structural mismatch of constructed value. " +
                "Parsed: #{num_parsed}  of #{actual_size} values")
            end
          end
        end
      end
      
      class TemplateParser
        class << self
          include TypeParser, TemplateUtil
          
          def parse(obj, asn1, definition)
            type = definition[:type]
            name = definition[:name]
            options = definition[:options]
            ignore = options[:parse_ignore]
            
            instance = type.parse(asn1, options)
            unless options[:parse_ignore]
              obj.instance_variable_set("@" + name.to_s, instance)
            end
          end
        end
      end
      
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
                define_method "#{meth_name}" do |name, opts={}|
                  attr_accessor name
                  deff = { type: type, 
                           name: name, 
                           options: opts, 
                           encoder: PrimitiveEncoder,
                           parser: PrimitiveParser }
                  cur_def[:inner_def] << deff
                end
              end
            end
            
            define_method :declare_cons do |meth_name, type|
              if !block_given?
                raise ArgumentError("#{meth_name} must be given a block.")
              end
              
              eigenclass.instance_eval do
                define_method "#{meth_name}" do |opts={}, &proc|
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
            
            define_method :asn1_template do |name, type, opts={}|
              attr_accessor name
              new_def = { type: type, 
                          name: name, 
                          options: opts, 
                          encoder: TemplateEncoder,
                          parser: TemplateParser }
              cur_def[:inner_def] << new_def
            end
            
            define_method :asn1_any do |name, opts={}|
              attr_accessor name
            end
            
            define_method :asn1_sequence_of do |type, name, opts={}|
              attr_accessor name
            end
            
            define_method :asn1_set_of do |type, name, opts={}|
              attr_accessor name
              puts "test"
            end
            
            define_method :asn1_choice do |name, opts={}, &proc|
              attr_accessor name
            end
              
          end
          
          declare_prim("asn1_boolean", OpenSSL::ASN1::Boolean)
          declare_prim("asn1_integer", OpenSSL::ASN1::Integer)
          declare_prim("asn1_bit_string", OpenSSL::ASN1::BitString)
          declare_prim("asn1_octet_string", OpenSSL::ASN1::OctetString)
          declare_prim("asn1_null", OpenSSL::ASN1::Null)
          declare_prim("asn1_object_id", OpenSSL::ASN1::ObjectId)
          declare_prim("asn1_enumerated", OpenSSL::ASN1::Enumerated)
          declare_prim("asn1_utf8_string", OpenSSL::ASN1::UTF8String)
          declare_prim("asn1_numeric_string", OpenSSL::ASN1::NumericString)
          declare_prim("asn1_printable_string", OpenSSL::ASN1::PrintableString)
          declare_prim("asn1_t61_string", OpenSSL::ASN1::T61String)
          declare_prim("asn1_videotex_string", OpenSSL::ASN1::VideotexString)
          declare_prim("asn1_ia5_string", OpenSSL::ASN1::IA5String)
          declare_prim("asn1_utc_time", OpenSSL::ASN1::UTCTime)
          declare_prim("asn1_generalized_time", OpenSSL::ASN1::GeneralizedTime)
          declare_prim("asn1_graphic_string", OpenSSL::ASN1::GraphicString)
          declare_prim("asn1_iso64_string", OpenSSL::ASN1::ISO64String)
          declare_prim("asn1_general_string", OpenSSL::ASN1::GeneralString)
          declare_prim("asn1_universal_string", OpenSSL::ASN1::UniversalString)
          declare_prim("asn1_bmp_string", OpenSSL::ASN1::BMPString)
          
          declare_cons("asn1_sequence", OpenSSL::ASN1::Sequence)
          declare_cons("asn1_set", OpenSSL::ASN1::Set)
          
          yield
        end
        
      end
    end
  end
end

class Validity
  include OpenSSL::ASN1::Template
  
  asn1_declare OpenSSL::ASN1::Sequence do
    asn1_utc_time :begin
    asn1_utc_time :end, {optional: true, tag: 0, tagging: :IMPLICIT}
    #asn1_utc_time :end, {optional: true, tag: 0, tagging: :EXPLICIT}
  end
end

class Certificate
  include OpenSSL::ASN1::Template
  
  asn1_declare OpenSSL::ASN1::Sequence do
    asn1_printable_string :subject
    asn1_integer :version, { default: 99 }
    asn1_boolean :qualified, { optional: true }
    asn1_printable_string :issuer
    asn1_template :validity, Validity, { tag: 1, tagging: :IMPLICIT }
  end
end


c = Certificate.new
c.subject = "Martin"
#c.version = 5
c.issuer = "Issuer"
c.validity.begin = Time.new
c.validity.end = Time.new

asn1 = c.to_asn1
#asn1.value.pop
#mod_asn1 = Array.new
#asn1.each do |e|
#  mod_asn1 << e unless e.value == "Martin"
#end
der = asn1.to_der
pp der
asn12 = OpenSSL::ASN1.decode(der)
pp asn12
c2 = Certificate.parse(asn12)
pp c2
puts c2.to_der == der

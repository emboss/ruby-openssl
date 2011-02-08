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

module OpenSSL::ASN1::Template
  module TemplateUtil
        
    def determine_tag_class(tag)
      if tag
        :CONTEXT_SPECIFIC
      else
        :UNIVERSAL
      end
    end
      
    def real_type(type)
      unless type.include? OpenSSL::ASN1::Template
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
end

require_relative 'template/encoder'
require_relative 'template/parser'

module OpenSSL::ASN1
  #Provides class methods that define the underlying ASN.1 structure of 
  #a class. Defining the structure in this manner also automatically adds
  #parsing and encoding facilities by adding a +to_der+ method to the
  #class instance and by providing a +parse+ class method in the class that
  #includes this module.
  #available options { optional: false, tag: nil, 
  #                    tagging: nil, default: nil }
  #definition { type, name, inner_def, options, parser, encoder }
  module Template
      
    def self.included(base)
      base.extend TemplateMethods
      tmp_self = self
      base.define_singleton_method :parse do |asn1, options={}, return_nil=false|
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
        
        unless Parser.parse_recursive(obj, asn1, definition)
          unless return_nil
            raise OpenSSL::ASN1::ASN1Error.new("Could not match
              type #{definition[:type]}")
          else
            nil
          end
        else
          obj
        end
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

    def set_infinite_length(value)
      instance_variable_set(:@infinite_length, value)
    end

    def set_infinite_length_iv(name, value, sizes=nil)
      val_iv = instance_variable_get(name)
      val_iv.instance_variable_set(:@infinite_length, value)
      if sizes
        val_iv.instance_variable_set(:@infinite_length_sizes, sizes)
      end
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
        mandatory = !(options[:optional] || options[:default])
        if type && type.include?(Template) && mandatory
          instance = type.new(options)
          instance_variable_set("@" + definition[:name].to_s, instance)
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
          
          define_method :declare_prim do |meth_name, 
                                          type, 
                                          parser=PrimitiveParser, 
                                          encoder=PrimitiveEncoder|
            eigenclass.instance_eval do
              define_method meth_name do |name=nil, opts={}|
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
            deff = { type: OpenSSL::ASN1::ASN1Data,
                     name: name, 
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
        declare_prim(:asn1_utf8_string, OpenSSL::ASN1::UTF8String, UTF8Parser)
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

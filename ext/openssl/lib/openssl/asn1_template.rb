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
    
    module Template

      DEF_OPTS_ASN1 = { optional: false, 
                        tag: nil, 
                        tagging: nil, 
                        infinite_length: false,
                        tag_class: nil }
                        
      def initialize(opts=nil)
        opts || opts = {}
        opts = DEF_OPTS_ASN1.merge(opts)
        @_options = opts
      end
      
      def to_der
        asn1_obj = to_asn1
        asn1_obj ? asn1_obj.to_der : nil
      end

      def to_asn1
        definition = self.class._definition
        definition[:options] = @_options
        definition ? to_asn1_obj_recursive(definition) : nil
      end
      
      private

      def to_asn1_obj_recursive(definition)
        options = definition[:options]
        type = definition[:type] 
        inner_def = definition[:inner_def]
        inf_length = options[:infinite_length]
        tag = options[:tag]
        tagging = options[:tagging]
        tag_class = options[:tag_class]
        
        if inner_def
          to_asn1_obj_cons(type, inner_def, inf_length, tag, tagging, tag_class)
        else
          name = definition[:name]
          value = instance_variable_get("@" + name.to_s)
          if value.respond_to? :to_asn1
            to_asn1_obj_templ(value, name, options)
          else
            to_asn1_obj_prim(value, type, name, inf_length, tag, tagging, tag_class)
          end
        end
      end
      
      def to_asn1_obj_templ(value, name, options)
        value.instance_variable_set(:@_options, options)
        value.to_asn1
      end
      
      def to_asn1_obj_cons(type, inner_def, inf_length, tag, tagging, tag_class)
        value = Array.new
        inner_def.each do |element|
          value << to_asn1_obj_recursive(element)
        end
        value << OpenSSL::ASN1::EndOfContent.new if inf_length
        constructed = unless tag
                        type.new(value)
                      else
                        type.new(value, tag, tagging, tag_class)
                      end
        constructed.infinite_length = inf_length
        constructed  
      end
      
      def to_asn1_obj_prim(value, type, name, inf_length, tag, tagging, tag_class)
        if inf_length
          return to_asn1_obj_prim_inf(value, type, name, tag, tagging, tag_class)
        end
        unless tag
          type.new(value)
        else
          type.new(value, tag, tagging, tag_class)
        end
      end
      
      def to_asn1_obj_prim_inf(value, type, name, tag, tagging, tag_class)
        tag_class = tag_class || :UNIVERSAL
        tag = tag || OpenSSL::ASN1.default_tag_class(type)
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

      def self.included(base)
        base.extend ClassMethods
      end

      module ClassMethods
        attr_reader :_definition
        
        def asn1_declare(type)
          @_definition = { type: type, options: nil, inner_def: Array.new }
          cur_def = @_definition
                    
          eigenclass = class << self; self; end
          
          eigenclass.instance_eval do
            
            define_method :declare_prim do |meth_name, type|
              eigenclass.instance_eval do
                define_method "#{meth_name}" do |name, opts={}|
                  cur_def[:inner_def] << _declare_primitive(type, name, opts)
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
                  opts = DEF_OPTS_ASN1.merge(opts)
                  cur_def = { type: type, options: opts, inner_def: Array.new }
                  proc.call
                  tmp_def[:inner_def] << cur_def
                  cur_def = tmp_def
                end
              end
            end
            
            define_method :asn1_template do |type, name, opts={}|
                attr_accessor name
                opts = DEF_OPTS_ASN1.merge(opts)
                cur_def[:inner_def] << { type: type, name: name, options: opts, inner_def: nil }
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

        def _declare_primitive(type, name, opts)
          attr_accessor name
          opts = DEF_OPTS_ASN1.merge(opts)
          { type: type, name: name, options: opts, inner_def: nil }
        end
      end
    end
  end
end

#class Test
#  include OpenSSL::ASN1::Template

#  asn1_declare OpenSSL::ASN1::Sequence do
#    asn1_boolean :bool_val, { optional: true }
#    asn1_integer :int_val
#    asn1_sequence ({ infinite_length: true }) do
#      asn1_integer :inner_int
#      asn1_boolean :inner_bool
#    end
#    asn1_octet_string :bytes, { infinite_length: true }
#    #asn1_template Extensions, :extensions, { optional: true, tag: 0, tagging: :EXPLICIT }
#  end
#end

class Validity
  include OpenSSL::ASN1::Template
  
  asn1_declare OpenSSL::ASN1::Sequence do
    asn1_utc_time :begin
    asn1_utc_time :end
  end
end

class Certificate
  include OpenSSL::ASN1::Template
  
  asn1_declare OpenSSL::ASN1::Sequence do
    asn1_printable_string :subject
    asn1_template Validity, :validity
  end
end

v = Validity.new
v.begin = Time.new
v.end = Time.new
c = Certificate.new
c.subject = "Martin"
c.validity = v

asn1 = c.to_asn1
pp asn1
pp asn1.to_der

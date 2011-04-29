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
  $Id: template.rb $
=end

module OpenSSL::ASN1
  #Provides class methods that define the underlying ASN.1 structure of 
  #a class. Defining the structure in this manner also automatically adds
  #parsing and encoding facilities by adding a +to_der+ method to the
  #class instance and by providing a +parse+ class method in the class that
  #includes this module.
  #available options { optional: false, tag: nil, 
  #                    tagging: nil, default: nil }
  #definition { type, name, inner_def, options, min_size, code }
  module Template

    def self.included(base)
      base.extend TemplateMethods
      base.extend OpenSSL::ASN1::Template::Parser
    end

    private

    module TemplateMethods
        
      def asn1_declare(template_type, inner_type=nil)
        @definition = { type: type_for_sym(template_type, inner_type),
                        options: nil, 
                        inner_def: Array.new,
                        min_size: 0,
                        codec: codec_for_sym(template_type) }
        cur_def = @definition

        unless template_type == :SEQUENCE || template_type == :SET
          attr_accessor :value
          @definition[:name] = :@value
        end

        eigenclass = class << self; self; end
        eigenclass.instance_eval do
          
          define_method :declare_prim do |meth_name, type|
            eigenclass.instance_eval do
              define_method meth_name do |name=nil, opts=nil|
                if name
                  attr_accessor name
                  iv_name = ('@' + name.to_s).to_sym
                else
                  iv_name = nil
                end

                deff = { type: type,
                         name: iv_name,
                         options: opts,
                         codec: :PRIMITIVE }
                cur_def[:inner_def] << deff
                increase_min_size(template_type, cur_def, opts)
              end
            end
          end
            
          define_method :declare_special_typed do |meth_name, codec|
            eigenclass.instance_eval do
              define_method meth_name do |type, name=nil, opts=nil|
                if name
                  attr_accessor name
                  iv_name = ('@' + name.to_s).to_sym
                else
                  iv_name = nil
                end

                deff = { type: type,
                         name: iv_name,
                         options: opts,
                         codec: codec }
                cur_def[:inner_def] << deff
                increase_min_size(template_type, cur_def, opts)
              end
            end
          end
            
          define_method :asn1_choice do |name, opts=nil, &proc|
            if name
              attr_accessor name
              iv_name = ('@' + name.to_s).to_sym
            else
              iv_name = nil
            end

            tmp_def = cur_def
            cur_def = { name: iv_name,
                        options: opts,
                        inner_def: Array.new,
                        codec: :CHOICE }
            proc.call
            tmp_def[:inner_def] << cur_def
            cur_def = tmp_def
            increase_min_size(template_type, cur_def, opts)
          end
              
        end

        declare_prim(:asn1_boolean, OpenSSL::ASN1::BOOLEAN)
        declare_prim(:asn1_integer, OpenSSL::ASN1::INTEGER)
        declare_prim(:asn1_bit_string, OpenSSL::ASN1::BIT_STRING)
        declare_prim(:asn1_octet_string, OpenSSL::ASN1::OCTET_STRING)
        declare_prim(:asn1_null, OpenSSL::ASN1::NULL)
        declare_prim(:asn1_object_id, OpenSSL::ASN1::OBJECT)
        declare_prim(:asn1_enumerated, OpenSSL::ASN1::ENUMERATED)
        declare_prim(:asn1_utf8_string, OpenSSL::ASN1::UTF8STRING)
        declare_prim(:asn1_numeric_string, OpenSSL::ASN1::NUMERICSTRING)
        declare_prim(:asn1_printable_string, OpenSSL::ASN1::PRINTABLESTRING)
        declare_prim(:asn1_t61_string, OpenSSL::ASN1::T61STRING)
        declare_prim(:asn1_videotex_string, OpenSSL::ASN1::VIDEOTEXSTRING)
        declare_prim(:asn1_ia5_string, OpenSSL::ASN1::IA5STRING)
        declare_prim(:asn1_utc_time, OpenSSL::ASN1::UTCTIME)
        declare_prim(:asn1_generalized_time, OpenSSL::ASN1::GENERALIZEDTIME)
        declare_prim(:asn1_graphic_string, OpenSSL::ASN1::GRAPHICSTRING)
        declare_prim(:asn1_iso64_string, OpenSSL::ASN1::ISO64STRING)
        declare_prim(:asn1_general_string, OpenSSL::ASN1::GENERALSTRING)
        declare_prim(:asn1_universal_string, OpenSSL::ASN1::UNIVERSALSTRING)
        declare_prim(:asn1_bmp_string, OpenSSL::ASN1::BMPSTRING)
        
        declare_special_typed(:asn1_template, :TEMPLATE)
        declare_special_typed(:asn1_sequence_of, :SEQUENCE_OF)
        declare_special_typed(:asn1_set_of, :SET_OF)
        
        yield if block_given?
      end
      
      private

      def type_for_sym(sym, type)
        case sym
          when :SEQUENCE then OpenSSL::ASN1::SEQUENCE
          when :SET then OpenSSL::ASN1::SET
          when :CHOICE then nil
          when :ANY then OpenSSL::ASN1::ASN1Data
          else type
        end
      end

      def codec_for_sym(sym)
        case sym
          when :SEQUENCE then :CONSTRUCTIVE
          when :SET then :CONSTRUCTIVE
          else sym 
        end
      end

      def increase_min_size(sym, cons_def, cur_opts)
        if sym == :SEQUENCE || sym == :SET
          return unless cons_def[:min_size]
          unless cur_opts
            cons_def[:min_size] += 1
          else
            default = cur_opts ? cur_opts[:default] : nil
            optional = cur_opts ? cur_opts[:optional] : nil
            unless optional || default != nil
              cons_def[:min_size] += 1
            end
          end
        end
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




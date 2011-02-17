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
      tag ? :CONTEXT_SPECIFIC : :UNIVERSAL
    end
      
    def real_type(type)
      if type.respond_to?(:parse)
        type.instance_variable_get(:@definition)[:type]
      else
        type
      end
    end
        
    def tag_or_default(tag, type)
      tag || OpenSSL::ASN1::CLASS_TAG_MAP[type]
    end
        
    def default_tag_of_type(type)
      tmp_type = real_type(type)
      OpenSSL::ASN1::CLASS_TAG_MAP[tmp_type]
    end
    
    def self.dup_definition_with_opts(definition, opts)
      if opts
        options = if definition[:options]
                    definition[:options].merge(opts)
                  else
                    opts
                  end
        {
          type: definition[:type],
          name: definition[:name],
          setter: definition[:setter],
          inner_def: definition[:inner_def],
          min_size: definition[:min_size],
          options: options,
          parser: definition[:parser],
          encoder: definition[:encoder]
        }
      else
        definition
      end
    end

    def tag(options)
      options ? options[:tag] : nil
    end

    def tagging(options)
      options ? options[:tagging] : nil
    end

    def default(options)
      options ? options[:default] : nil
    end

    def optional(options)
      options ? options[:optional] : false
    end

  end
end

require_relative 'encoder'
require_relative 'parser'

module OpenSSL::ASN1
  #Provides class methods that define the underlying ASN.1 structure of 
  #a class. Defining the structure in this manner also automatically adds
  #parsing and encoding facilities by adding a +to_der+ method to the
  #class instance and by providing a +parse+ class method in the class that
  #includes this module.
  #available options { optional: false, tag: nil, 
  #                    tagging: nil, default: nil }
  #definition { type, name, setter, inner_def, options, parser, encoder }
  module Template
      
    def self.included(base)
      base.extend TemplateMethods
      base.define_singleton_method :parse do |asn1, options=nil, return_nil=false|
        definition = TemplateUtil.dup_definition_with_opts(@definition, options)
        
        unless asn1 || (options && options[:optional])
          raise OpenSSL::ASN1::ASN1Error.new(
          "Mandatory parameter not set. Type: #{definition[:type]} " +
          " Name: #{definition[:name]}")
        end
          
        return nil unless asn1
          
        unless asn1.respond_to?(:to_der)
          asn1 = OpenSSL::ASN1.decode(asn1)
          obj = base.new(nil, true)
        else
          obj = base.new(options, true)  
        end
        
        unless definition[:parser].parse(obj, asn1, definition)
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
      
    def initialize(options=nil, parse=false)
      if options != nil && !options.is_a?(Hash)
        parse_raw(options)
      else
        @options = options
        init_mandatory_templates_defaults(self.class.instance_variable_get(:@definition), parse)
      end
    end
      
    def to_der
      asn1_obj = to_asn1
      asn1_obj ? asn1_obj.to_der : nil
    end

    def to_asn1
      definition = TemplateUtil.dup_definition_with_opts(self.class.instance_variable_get(:@definition), @options)
      definition[:encoder].to_asn1(self, definition)
    end

    def to_asn1_iv(iv)
      self.class.instance_variable_get(:@definition)[:inner_def].each do |deff|
        if deff[:name] && deff[:name] == iv
          return deff[:encoder].to_asn1(self, deff)
        end
      end
      raise OpenSSL::ASN1::ASN1Error.new("No definition found for #{iv}")
    end

    def to_der_iv(name)
      to_asn1_iv(name).to_der
    end

    def set_infinite_length(value)
      instance_variable_set(:@infinite_length, value)
    end

    def set_infinite_length_iv(name, value, sizes=nil)
      val_iv = send(name)
      val_iv.instance_variable_set(:@infinite_length, value)
      if sizes
        unless sizes.respond_to?(:each)
          chunk_size = sizes
          sizes = Array.new
          val_size = val_iv.bytesize
          this_many = val_size / chunk_size
          this_many.times do
            sizes << chunk_size
          end
          rest = val_size - (this_many * chunk_size)
          sizes << rest if rest != 0
        end
        val_iv.instance_variable_set(:@infinite_length_sizes, sizes)
      end
    end

    private
      
    def parse_raw(raw)
      asn1 = raw.respond_to?(:to_der) ? raw : OpenSSL::ASN1.decode(raw)
      definition = self.class.instance_variable_get(:@definition)
      definition[:parser].parse(self, asn1, definition)
    end
      
    def init_mandatory_templates_defaults(definition, parse)
      definition[:inner_def].each do |deff|
        unless parse
          mandatory = !(deff[:options] && (deff[:options][:optional] || deff[:options][:default]))
          if mandatory && deff[:name] && deff[:type] && deff[:type].include?(Template)
            instance = deff[:type].new(deff[:options])
            send(deff[:setter], instance)
          end
        end
        
        default = if (deff[:options])
                    deff[:options][:default]
                  else
                    nil
                  end
        if default != nil
          send(deff[:setter], default)
        end
      end
    end
    
    module TemplateMethods
        
      def asn1_declare(template_type, inner_type=nil)
        @definition = { type: type_for_sym(template_type, inner_type),
                         options: nil, 
                         inner_def: Array.new,
                         min_size: 0,
                         encoder: encoder_for_sym(template_type),
                         parser: parser_for_sym(template_type) }
        cur_def = @definition

        unless template_type == :SEQUENCE || template_type == :SET
          attr_accessor :value
          @definition[:name] = :value
          @definition[:setter] = :value=
        end

        eigenclass = class << self; self; end
        eigenclass.instance_eval do
          
          define_method :declare_prim do |meth_name,
                                          type,
                                          parser=PrimitiveParser,
                                          encoder=PrimitiveEncoder|
            eigenclass.instance_eval do
              define_method meth_name do |name=nil, opts=nil|
                attr_accessor name if name
                
                deff = { type: type, 
                         name: name,
                         setter: name.to_s + '=',
                         options: opts, 
                         encoder: encoder,
                         parser: parser }
                cur_def[:inner_def] << deff
                increase_min_size(template_type, cur_def, opts)
              end
            end
          end
            
          define_method :declare_special_typed do |meth_name, encoder, parser|
            eigenclass.instance_eval do
              define_method meth_name do |type, name=nil, opts=nil|
                attr_accessor name if name
                deff = { type: type,
                         name: name,
                         setter: name.to_s + '=',
                         options: opts,
                         encoder: encoder,
                         parser: parser }
                cur_def[:inner_def] << deff
                increase_min_size(template_type, cur_def, opts)
              end
            end
          end
            
          define_method :asn1_choice do |name, opts=nil, &proc|
            attr_accessor name
            tmp_def = cur_def
            cur_def = { name: name,
                        setter: name.to_s + '=',
                        options: opts,
                        inner_def: Array.new,
                        encoder: ChoiceEncoder,
                        parser: ChoiceParser }
            proc.call
            tmp_def[:inner_def] << cur_def
            cur_def = tmp_def
            increase_min_size(template_type, cur_def, opts)
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
        
        yield if block_given?
      end
      
      private

      def type_for_sym(sym, type)
        case sym
          when :SEQUENCE then OpenSSL::ASN1::Sequence
          when :SET then OpenSSL::ASN1::Set
          when :CHOICE then nil
          when :ANY then OpenSSL::ASN1::ASN1Data
          else type
        end
      end

      def encoder_for_sym(sym)
          case sym
            when :SEQUENCE then ConstructiveEncoder
            when :SET then ConstructiveEncoder
            when :CHOICE then ChoiceEncoder
            when :SEQUENCE_OF then SequenceOfEncoder
            when :SET_OF then SetOfEncoder
            when :ANY then AnyEncoder
            else raise OpenSSL::ASN1::ASN1Error.new("Not supported: #{sym}")
          end
      end

      def parser_for_sym(sym)
          case sym
            when :SEQUENCE then ConstructiveParser
            when :SET then ConstructiveParser
            when :SEQUENCE_OF then SequenceOfParser
            when :SET_OF then SetOfParser
            when :CHOICE then ChoiceParser
            when :ANY then AnyParser
            else raise OpenSSL::ASN1::ASN1Error.new("Not supported: #{sym}")
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

module OpenSSL::ASN1

  class Any
    include OpenSSL::ASN1::Template

    asn1_declare :ANY
  end

end
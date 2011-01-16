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
    module Template

      DEF_OPTS_ASN1 = { optional: false, 
                        tag: nil, 
                        tagging: nil, 
                        infinite_length: false,
                        tag_class: nil }
                        
      #TODO: Handle EndOfContent
                  
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
        if definition[:inner_def] != nil
          type = definition[:type]
          value = Array.new
          definition[:inner_def].each do |element|
            value << to_asn1_obj_recursive(element)
          end
          constructed = unless options && options[:tag]
                          type.new(value)
                        else
                          type.new(value, options[:tag], options[:tagging], options[:tag_class])
                        end
          constructed.infinite_length = options[:infinite_length] if options
          return constructed
        end

        #primitive
        unless options && options[:tag]
          definition[:type].new(send(definition[:name]))
        else
          definition[:type].new(send(definition[:name]),
                                options[:tag],
                                options[:tagging],
                                options[:tag_class])
        end
      end

      def self.included(base)
        base.extend ClassMethods
      end

      module ClassMethods
        attr_reader :_definition
        
        def asn1_template(type, name, opts=nil, &inner)
          #like this
          templ.new(tag, tagging, infinite_length, tag_class).to_asn1
        end
        
        def asn1_declare(type)
          @_definition = { type: type, opts: nil, inner_def: Array.new }
          cur_def = @_definition
                    
          eigenclass = class << self; self; end
          eigenclass.instance_eval do
            
            define_method :declare_prim do |meth_name, type|
              eigenclass.instance_eval do
                define_method "#{meth_name}" do |name, opts=nil|
                  cur_def[:inner_def] << _declare_primitive(type, name, opts)
                end
              end
            end
            
            define_method :declare_cons do |meth_name, type|
              if !block_given?
                raise ArgumentError("#{meth_name} must be given a block.")
              end
              eigenclass.instance_eval do
                define_method "#{meth_name}" do |opts=nil, &proc|
                  tmp_def = cur_def
                  cur_def = { type: type, opts: opts, inner_def: Array.new }
                  proc.call
                  tmp_def[:inner_def] << cur_def
                  cur_def = tmp_def
                end
              end
            end
          end
                              
          declare_prim("asn1_boolean", OpenSSL::ASN1::Boolean)
          declare_prim("asn1_integer", OpenSSL::ASN1::Integer)
          
          declare_cons("asn1_sequence", OpenSSL::ASN1::Sequence)
          
          yield
        end

        def _declare_primitive(type, name, opts)
          attr_accessor name
          opts || opts = {}
          opts = DEF_OPTS_ASN1.merge(opts)
          opts[:name] = name
          { type: type, name: name, options: opts, inner_def: nil }
        end
      end
    end
  end
end

class Test
  include OpenSSL::ASN1::Template

  asn1_declare OpenSSL::ASN1::Sequence do
    asn1_boolean :bool_val, { optional: true }
    asn1_integer :int_val
    asn1_sequence do
      asn1_integer :inner_int
      asn1_boolean :inner_bool
    end
    asn1_integer :other_int
    #asn1_template Extensions, :extensions, { optional: true, tag: 0, tagging: :EXPLICIT }
  end
end

t = Test.new
t.bool_val = false
t.int_val = 5
t.inner_int = 10
t.inner_bool = true
t.other_int = 0
asn1 = t.to_asn1
pp asn1
pp asn1.to_der

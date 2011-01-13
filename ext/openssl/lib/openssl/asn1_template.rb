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

      DEF_OPTS_INIT = { tag: nil, 
                        tagging: nil, 
                        infinite_length: false,
                        tag_class: nil }
                        
      def initialize(opts=nil)
        opts || opts = {}
        opts = DEF_OPTS_INIT.merge(opts)
        @type = self.class._type
        @tag = opts[:tag]
        @tagging = opts[:tagging]
        @infinite_length = opts[:infinite_length]
        @tag_class = opts[:tag_class]
      end
      
      def to_der
        asn1_obj = to_asn1
        asn1_obj ? asn1_obj.to_der : nil
      end

      def to_asn1
        asn1 = self.class._asn1
        value = asn1 ? to_asn1_obj_recursive(asn1) : nil
        constructed = unless @tag
                        @type.new(value)
                      else
                        @type.new(value, @tag, @tagging, @tag_class)
                      end
        constructed.infinite_length = @infinite_length if @infinite_length
        constructed
      end
      
      private

      def to_asn1_obj_recursive(asn1)
        case asn1
        when Array
          content = Array.new
          asn1.each do |element|
            content << to_asn1_obj_recursive(element)
          end
          return content
        end

        #primitive
        asn1[:type].new(send(asn1[:name]))
      end

      def self.included(base)
        base.extend ClassMethods
      end

      module ClassMethods
        attr_reader :_asn1
        attr_reader :_type

        DEF_OPTS_PRIM = { optional: false, 
                          tag: nil, 
                          tagging: nil, 
                          infinite_length: false,
                          tag_class: nil }

        def asn1_boolean(name, opts=nil)
          @_asn1 << _declare_primitive(OpenSSL::ASN1::Boolean, name, opts)
        end

        def asn1_integer(name, opts=nil)
          @_asn1 << _declare_primitive(OpenSSL::ASN1::Integer, name, opts)
        end

        def asn1_template(type, name, opts=nil, &inner)
          
        end
        
        def asn1_declare(type)
          @_asn1 = Array.new
          @_type = type
          cur_asn1 = @_asn1
          last_asn1 = nil
          
          define_method define_prim do |meth_name, type|
            define_method "#{meth_name}" do |name, opts=nil|
              cur_asn1 << _declare_primitive(type, name, opts)
            end
          end
          
          define_prim("asn1_boolean", OpenSSL::ASN1::Boolean)
          define_prim("asn1_integer", OpenSSL::ASN1::Integer)
          
          if block_given?
            yield
          else 
            raise ArgumentError("asn1_declare must be given a block.")
          end
        end

        def _declare_primitive(type, name, opts)
          attr_accessor name
          opts || opts = {}
          opts = DEF_OPTS_PRIM.merge(opts)
          { name: name, type: type }.merge(opts)
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
    #asn1_sequence :seq_val do
    #  asn1_boolean :inner_bool
    #  asn1_integer :inner_int
    #end
    #asn1_integer :other_int
    #asn1_template Extensions, :extensions, { optional: true, tag: 0, tagging: :EXPLICIT }
  end
end

t = Test.new
t.bool_val = false
t.int_val = 5
asn1 = t.to_asn1
pp asn1
pp asn1.to_der

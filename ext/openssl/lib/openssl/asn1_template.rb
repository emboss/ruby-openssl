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

      def to_der
        asn1 = self.class._asn1
        pp asn1
        return nil if asn1 == nil
        asn1_obj = to_der_recursive(asn1)
        asn1_obj.to_der
      end

      private

      def to_der_recursive(asn1)
        case asn1
        when Array
          content = Array.new
          asn1.each do |element|
            content << to_der_recursive(element)
          end
          return OpenSSL::ASN1::Sequence.new(content)
        end

        #primitive
        asn1[:type].new(send(asn1[:name]))
      end

      def self.included(base)
        base.extend ClassMethods
      end

      module ClassMethods
        attr_reader :_asn1

        DEF_OPTS_PRIM = { optional: false, tag: nil, tagging: nil }

        def asn1_boolean(name, opts=nil)
          @_asn1 << _declare_primitive(OpenSSL::ASN1::Boolean, name, opts)
        end

        def asn1_integer(name, opts=nil)
          @_asn1 << _declare_primitive(OpenSSL::ASN1::Integer, name, opts)
        end

        def asn1_template(&inner)
          @_asn1 = Array.new
          yield
        end

        def _declare_primitive(type, name, opts)
          attr_accessor name
          opts || opts = {}
          opts = DEF_OPTS_PRIM.merge(opts)
          { :name => name, :type => type }.merge(opts)
        end
      end
    end
  end
end

class Test
  include OpenSSL::ASN1::Template

  asn1_template OpenSSL::ASN1::Sequence do
    asn1_boolean :bool_val, { optional: true }
    asn1_integer :int_val
    asn1_sequence :seq_val do
      asn1_boolean :inner_bool
      asn1_integer :inner_int
    end
    asn1_integer :other_int
    asn1_template Extensions, :extensions, { optional: true, tag: 0, tagging: :EXPLICIT }
  end

end

t = Test.new
t.bool_val = false
t.int_val = 5
pp t.to_der

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
require 'pp'

module OpenSSL
  module ASN1
    #Provides class methods that define the underlying ASN.1 structure of 
    #a class. Defining the structure in this manner also automatically adds
    #parsing and encoding facilities by adding a +to_der+ method to the
    #class instance and by providing a +parse+ class method in the class that
    #includes this module.
    module Template

      def to_der
        asn1_ary = self.class._asn1
        pp asn1_ary
        return nil if (asn1_ary == nil || asn1_ary.empty?)
        asn1_obj = to_der_recursive(asn1)
        asn1_obj.to_der
      end

      private

      def to_der_recursive(asn1)
        if asn1.is_a? Array
          return nil
        end

        case asn1.type
        when :ASN1_BOOLEAN
          return OpenSSL::ASN1::Boolean.new(send(asn1.name))
        when :ASN1_INTEGER
          return OpenSSL::ASN1::Integer.new(send(asn1.name))
        end
      end

      def self.included(base)
        base.extend ClassMethods
      end

      Meta = Struct.new(:name, :type, :optional, :tag, :tag_mode)

      module ClassMethods
        attr_reader :_asn1
        
        def asn1_boolean(name, optional, tag=nil, tag_mode=nil)
          _declare_primitive(:ASN1_BOOLEAN, name, optional, tag, tag_mode)
        end

        def asn1_integer(name, optional, tag=nil, tag_mode=nil)
          _declare_primitive(:ASN1_INTEGER, name, optional, tag, tag_mode)
        end

        def asn1_sequence(name, optional, tag=nil, tag_mode=nil, &inner)

        end

        def _declare_primitive(type, name, optional, tag, tag_mode)
          attr_accessor name
          @_asn1 || @_asn1 = Array.new
          info = Meta.new(name, type, optional, tag, tag_mode)
          @_asn1 << info
        end
      end
    end
  end
end

class Test
  include OpenSSL::ASN1::Template

#  asn1_boolean :mudda, :OPTIONAL
  asn1_integer :deine, :MANDATORY
end

t = Test.new
#t.mudda = "Test"
t.deine = 5
pp t.to_der

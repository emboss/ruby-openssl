/*
 * $Id: ossl_asn1-internal.h$
 * Copyright (C) 2011 Martin Bosslet <Martin.Bosslet@googlemail.com>
 * All rights reserved.
 *
 * 
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(_OSSL_ASN1_INTERNAL_H_)
#define _OSSL_ASN1_INTERNAL_H_

/*
 * Ruby to ASN1 converters
 */
ASN1_BOOLEAN obj_to_asn1bool(VALUE obj);
ASN1_INTEGER* obj_to_asn1int(VALUE obj);
ASN1_BIT_STRING* obj_to_asn1bstr(VALUE obj, long unused_bits);
ASN1_STRING* obj_to_asn1str(VALUE obj);
ASN1_NULL* obj_to_asn1null(VALUE obj);
ASN1_OBJECT* obj_to_asn1obj(VALUE obj);
ASN1_UTCTIME* obj_to_asn1utime(VALUE time);
ASN1_GENERALIZEDTIME* obj_to_asn1gtime(VALUE time);
ASN1_STRING* obj_to_asn1derstr(VALUE obj);

/*
 * DER to Ruby converters
 */
VALUE decode_bool(unsigned char* der, int length);
VALUE decode_int(unsigned char* der, int length);
VALUE decode_bstr(unsigned char* der, int length, long *unused_bits);
VALUE decode_enum(unsigned char* der, int length);
VALUE decode_null(unsigned char* der, int length);
VALUE decode_obj(unsigned char* der, int length);
VALUE decode_time(unsigned char* der, int length);


#endif

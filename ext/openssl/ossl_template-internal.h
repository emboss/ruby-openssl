/*
 * $Id: ossl_template-internal.h$
 * Copyright (C) 2011 Martin Bosslet <Martin.Bosslet@googlemail.com>
 * All rights reserved.
 *
 * 
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(_OSSL_TEMPLATE_INTERNAL_H_)
#define _OSSL_TEMPLATE_INTERNAL_H_

extern VALUE cChoiceValue;

extern ID sOPTIONS, sDEFAULT, sNAME, sTYPE, 
	  sOPTIONAL, sTAG, sTAGGING, sINNER_DEF,
	  sMIN_SIZE, sCODEC; 
	  
extern ID sPRIMITIVE, sCONSTRUCTIVE, sTEMPLATE,
	  sSEQUENCE_OF, sSET_OF, sCHOICE, sANY;

extern ID sIMPLICIT, sEXPLICIT;

extern ID sVALUE, sMERGE;

extern ID sivDEFINITION, sivOPTIONS, sivUNUSED_BITS,
	  sivTYPE, sivINFINITE_LENGTH;

typedef struct asn1_def_st {
    VALUE definition;
    VALUE values[10];
    int value_read[10];
} asn1_def_t;

#define ASN1_DEF_OPTIONS 0
#define ASN1_DEF_TYPE 1
#define ASN1_DEF_NAME 2
#define ASN1_DEF_CODEC 3
#define ASN1_DEF_INNER_DEF 4
#define ASN1_DEF_TAG 5
#define ASN1_DEF_TAGGING 6
#define ASN1_DEF_OPTIONAL 7
#define ASN1_DEF_DEFAULT_VALUE 8
#define ASN1_DEF_MIN_SIZE 9
#define ASN1_DEF_NUM_VALUES 10

#define ossl_template_get_definition(o)		rb_ivar_get((o), sivDEFINITION)
#define ossl_template_get_options(o)		rb_ivar_get((o), sivOPTIONS)
#define ossl_template_set_options(o, v)		rb_ivar_set((o), sivOPTIONS, (v))
#define ossl_template_get_unused_bits(o)	rb_ivar_get((o), sivUNUSED_BITS)
#define ossl_template_set_unused_bits(o, v)	rb_ivar_set((o), sivUNUSED_BITS, (v))
#define ossl_template_get_infinite_length(o)	rb_ivar_get((o), sivINFINITE_LENGTH)
#define ossl_template_set_infinite_length(o, v)	rb_ivar_set((o), sivINFINITE_LENGTH, (v))

#define ossl_template_hash_get_options(o)	rb_hash_aref((o), ID2SYM(sOPTIONS))
#define ossl_template_hash_get_default(o)	rb_hash_aref((o), ID2SYM(sDEFAULT))
#define ossl_template_hash_get_name(d)		rb_hash_aref((d), ID2SYM(sNAME))
#define ossl_template_hash_get_type(d)		rb_hash_aref((d), ID2SYM(sTYPE))
#define ossl_template_hash_get_optional(d)	rb_hash_aref((d), ID2SYM(sOPTIONAL))
#define ossl_template_hash_get_tag(d)	 	rb_hash_aref((d), ID2SYM(sTAG))
#define ossl_template_hash_get_tagging(d)	rb_hash_aref((d), ID2SYM(sTAGGING))
#define ossl_template_hash_get_inner_def(d)	rb_hash_aref((d), ID2SYM(sINNER_DEF))
#define ossl_template_hash_get_min_size(d)	rb_hash_aref((d), ID2SYM(sMIN_SIZE))
#define ossl_template_hash_get_codec(d)	 	rb_hash_aref((d), ID2SYM(sCODEC))

/* asn1_def_t serves as a proxy object for the definition hash.
 * Hash access is a costly operation, therefore access is
 * minimized by using this approach.
 */
void asn1_def_init(asn1_def_t *def);

void int_ossl_template_initialize(VALUE self, VALUE options, int parse);
long int_ossl_template_parse(VALUE obj, asn1_def_t *def, unsigned char **pp, long max_length);

void Init_ossl_template_parse(void);

#endif


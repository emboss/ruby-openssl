/*
 * $Id: ossl_asn1_template.c$
 * Copyright (C) 2011 Martin Bosslet <Martin.Bosslet@googlemail.com>
 * All rights reserved.
 *
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"
#include "ossl_asn1-internal.h"
#include "ossl_template-internal.h"

VALUE mTemplate;
VALUE eTemplateError;
VALUE cChoiceValue;

ID sOPTIONS, sDEFAULT, sNAME, sTYPE, 
	  sOPTIONAL, sTAG, sTAGGING, sINNER_DEF,
	  sMIN_SIZE, sCODEC; 
	  
ID sPRIMITIVE, sCONSTRUCTIVE, sTEMPLATE,
	  sSEQUENCE_OF, sSET_OF, sCHOICE, sANY;

ID sIMPLICIT, sEXPLICIT;

ID sVALUE, sMERGE;

ID sivDEFINITION, sivOPTIONS, sivUNUSED_BITS,
	  sivTYPE, sivINFINITE_LENGTH;

static VALUE int_ossl_template_dup_def_with_opts(VALUE def, VALUE options);
static void int_ossl_template_init_mandatory_and_defaults(VALUE self, VALUE def, int parse);

void
asn1_def_init(asn1_def_t *def)
{
    int i;
    def->definition = Qnil;
    for (i = 0; i < ASN1_DEF_NUM_VALUES; i++) { 
	def->values[i] = Qnil;
	def->value_read[i] = 0;
    }
}

static VALUE
int_ossl_template_dup_def_with_opts(VALUE def, VALUE options) 
{
    VALUE new_options;
    VALUE def_options;
    VALUE hash;
	
    if (options == Qnil)
	return def;
    
    def_options = ossl_template_hash_get_options(def);
    new_options = def_options != Qnil ? 
		  rb_funcall(def_options, sMERGE, 1, options) : 
		  options;

    hash = rb_hash_new();

    rb_hash_aset(hash, sTYPE, ossl_template_hash_get_type(def));
    rb_hash_aset(hash, sNAME, ossl_template_hash_get_name(def));
    rb_hash_aset(hash, sINNER_DEF, ossl_template_hash_get_inner_def(def));
    rb_hash_aset(hash, sMIN_SIZE, ossl_template_hash_get_min_size(def));
    rb_hash_aset(hash, sOPTIONS, options);
    rb_hash_aset(hash, sCODEC, ossl_template_hash_get_codec(def));

    return hash;
}



static VALUE
ossl_template_to_der(VALUE self)
{
    VALUE def, options;

    def = ossl_template_get_definition(CLASS_OF(self));
    options = ossl_template_get_options(self);

    def = int_ossl_template_dup_def_with_opts(def, options);
    /* TODO */
    return Qnil;
}

static VALUE
ossl_template_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE der, def;
    unsigned char *p;
    long offset = 0;
    volatile VALUE tmp;

    //printf("Top level init\n");

    rb_scan_args(argc, argv, "01", &der);
    if (!NIL_P(der)) {
	def = ossl_template_get_definition(CLASS_OF(self));
	der = ossl_to_der_if_possible(der);
	tmp = rb_str_new4(StringValue(der));
	p = (unsigned char *)RSTRING_PTR(tmp);
	asn1_def_t asn1_def;
	asn1_def_init(&asn1_def);
	asn1_def.definition = def;
	if (!int_ossl_template_parse(self, &asn1_def, &p, RSTRING_LEN(tmp))) {
	    VALUE type = ossl_template_hash_get_type(def);
	    ossl_raise(eTemplateError,
		       "Could not match type %s",
		       rb_class2name(type));
	    return Qnil;
	}
    }
    else {
	int_ossl_template_initialize(self, Qnil, 0);
    }
    
    return self;
}

void
int_ossl_template_initialize(VALUE self, VALUE options, int parse)
{
    VALUE def;

    //printf("Inner init %s\n", rb_class2name(CLASS_OF(self)));

    def = ossl_template_get_definition(CLASS_OF(self));

    if (!NIL_P(options)) {
	ossl_template_set_options(self, options);
    }
    int_ossl_template_init_mandatory_and_defaults(self, def, parse);
}

static void
int_ossl_template_init_mandatory_and_defaults_i(VALUE inner_def, VALUE self, int parse)
{
    VALUE options, optional, default_val = Qnil, type, name;
    int mandatory;

    options = ossl_template_hash_get_options(inner_def);
    if (options != Qnil)
	default_val = ossl_template_hash_get_default(options);

    if (!parse) {
	mandatory = options == Qnil || 
	            !(ossl_template_hash_get_optional(options) == Qtrue ||
		    ossl_template_hash_get_default_value(options) != Qnil);

	type = ossl_template_hash_get_type(inner_def);
	name = ossl_template_hash_get_name(inner_def);
	if (mandatory && 
	    name != Qnil &&
	    type != Qnil &&
	    TYPE(type) == T_CLASS &&
	    rb_mod_include_p(type, mTemplate)) {
	    VALUE obj = rb_obj_alloc(type);
	    int_ossl_template_initialize(obj, options, 0);
	    rb_ivar_set(self, SYM2ID(name), obj);
	}
    }
    
    if (default_val != Qnil && name != Qnil) {
	rb_ivar_set(self, SYM2ID(name), default_val);
    }
}

static void
int_ossl_template_init_mandatory_and_defaults(VALUE self, VALUE def, int parse)
{
    VALUE inner_def_ary, inner_def, args;
    long idef_size;
    int i;

    inner_def_ary = ossl_template_hash_get_inner_def(def);
    idef_size = RARRAY_LEN(inner_def_ary);
    for (i = 0; i < idef_size; i++) {
	inner_def = rb_ary_entry(inner_def_ary, i);
	int_ossl_template_init_mandatory_and_defaults_i(inner_def, self, parse);
    }
}

void
Init_ossl_template()
{

#if 0
    mOSSL = rb_define_module("OpenSSL"); /* let rdoc know about mOSSL */
#endif

    sOPTIONS = rb_intern("options");
    sDEFAULT = rb_intern("default");
    sNAME = rb_intern("name");
    sTYPE = rb_intern("type");
    sOPTIONAL = rb_intern("optional");
    sTAG = rb_intern("tag");
    sTAGGING = rb_intern("tagging");
    sINNER_DEF = rb_intern("inner_def");
    sMIN_SIZE = rb_intern("min_size");
    sCODEC = rb_intern("codec");

    sPRIMITIVE = rb_intern("PRIMITIVE");
    sCONSTRUCTIVE = rb_intern("CONSTRUCTIVE");
    sTEMPLATE = rb_intern("TEMPLATE");
    sSEQUENCE_OF = rb_intern("SEQUENCE_OF");
    sSET_OF = rb_intern("SET_OF");
    sCHOICE = rb_intern("CHOICE");
    sANY = rb_intern("ANY");

    sIMPLICIT = rb_intern("IMPLICIT");
    sEXPLICIT = rb_intern("EXPLICIT");

    sVALUE = rb_intern("@value");
    sMERGE = rb_intern("merge");

    sivDEFINITION = rb_intern("@definition");
    sivOPTIONS = rb_intern("@options");
    sivUNUSED_BITS = rb_intern("@unused_bits");
    sivINFINITE_LENGTH = rb_intern("@infinite_length");
    sivTYPE = rb_intern("@type");

    mTemplate = rb_define_module_under(mASN1, "Template");
    eTemplateError = rb_define_class_under(mTemplate, "TemplateError", eOSSLError);

    /* implementation is in template.rb */
    cChoiceValue = rb_define_class_under(mTemplate, "ChoiceValue", rb_cObject);

    rb_define_method(mTemplate, "initialize", ossl_template_initialize, -1);
    rb_define_method(mTemplate, "to_der", ossl_template_to_der, 0);

    Init_ossl_template_parse();
}


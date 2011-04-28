/*
 * $Id: ossl_asn1_template.c$
 * Copyright (C) 2011 Martin Bosslet <Martin.Bosslet@googlemail.com>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

VALUE mTemplate;
VALUE mParser;
VALUE eTemplateError;

static ID sOPTIONS, sDEFAULT, sNAME, sTYPE, 
	  sOPTIONAL, sTAG, sTAGGING, sINNER_DEF,
	  sMIN_SIZE, sCODEC; 
	  

static ID sPRIMITIVE, sCONSTRUCTIVE, sTEMPLATE,
	  sSEQUENCE_OF, sSET_OF, sCHOICE;

#define ossl_template_get_definition(o)		rb_iv_get((o), "@definition")
#define ossl_template_get_options(o)		rb_iv_get((o), "@options")
#define ossl_template_set_options(o, v)		rb_iv_set((o), "@options", (v))

#define ossl_template_hash_get_options(o)	rb_hash_aref((o), sOPTIONS)
#define ossl_template_hash_get_default(o)	rb_hash_aref((o), sDEFAULT)
#define ossl_template_hash_get_name(d)		rb_hash_aref((d), sNAME)
#define ossl_template_hash_get_type(d)		rb_hash_aref((d), sTYPE)
#define ossl_template_hash_get_optional(d)	rb_hash_aref((d), sOPTIONAL)
#define ossl_template_hash_get_tag(d)	 	rb_hash_aref((d), sTAG)
#define ossl_template_hash_get_tagging(d)	rb_hash_aref((d), sTAGGING)
#define ossl_template_hash_get_inner_def(d)	rb_hash_aref((d), sINNER_DEF)
#define ossl_template_hash_get_min_size(d)	rb_hash_aref((d), sMIN_SIZE)
#define ossl_template_hash_get_codec(d)	 	rb_hash_aref((d), sCODEC)


static void int_ossl_template_initialize(VALUE self, VALUE options, int parse);
static void  int_ossl_template_init_mandatory_and_defaults(VALUE self, VALUE def, int parse);
static int int_ossl_template_parse(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static int parse_primitive(VALUE obj, VALUE def, unsigned char **pp, long length, int tag, int tag_class);
/* static int parse_template(VALUE obj, VALUE def, unsigned char **pp, long length, long *offset); */
/* static int parse_constructive(VALUE obj, VALUE def, unsigned char **pp, long length, long *offset); */
/* static int parse_seq_of(VALUE obj, VALUE def, unsigned char **pp, long max_length); */
/* static int parse_set_of(VALUE obj, VALUE def, unsigned char **pp, long max_length); */
/* static int parse_choice(VALUE obj, VALUE def, unsigned char **pp, long max_length); */
static void parse_header(unsigned char **pp, long max_length, long *len, int *j, int *tag, int *tc, int *hlen);
static int match0(int tag, int tag_class, VALUE type, VALUE name, VALUE options, int force_optional);
static int match(int tag, int tag_class, VALUE type, VALUE name, VALUE options);
static int tag_or_default(VALUE tag, VALUE type);
static int determine_tag_class(VALUE tag);
static VALUE int_ossl_template_dup_def_with_opts(VALUE def, VALUE options);


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
		  rb_funcall(def_options, rb_intern("merge"), 1, options) : 
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

static int
tag_or_default(VALUE tag, VALUE type)
{
    return tag == Qnil ? FIX2INT(type) : FIX2INT(tag);
}

static int
determine_tag_class(VALUE tag)
{
    return tag == Qnil ? V_ASN1_UNIVERSAL : V_ASN1_CONTEXT_SPECIFIC;
}

static void
parse_header(unsigned char **pp, long max_length, long *len, int *j, int *tag, int *tc, int *hlen)
{
    unsigned char *start, *p;
    const unsigned char *p0;
    p = *pp;
    start = p;
    p0 = p;
    *j = ASN1_get_object(&p0, len, tag, tc, max_length);
    p = (unsigned char *)p0;
    if (*j & 0x80) ossl_raise(eTemplateError, NULL);
    *hlen = p - start;
    *pp = p;
}

static int
match(int tag, int tag_class, VALUE type, VALUE name, VALUE options)
{
    return match0(tag, tag_class, type, name, options, 0);
}

static int
match0(int tag, int tag_class, VALUE type, VALUE name, VALUE options, int force_optional)
{
    VALUE opt_tag, optional, default_val;
    const char *c_name;

    opt_tag = options == Qnil ? Qnil : ossl_template_hash_get_tag(options);
    if (tag == tag_or_default(opt_tag, type))
    {
	if (!tag_class == determine_tag_class(opt_tag)) {
	    ossl_raise(eTemplateError,
		       "Tag class mismatch. Expected: %s"
		       "Got: %s",
		       determine_tag_class(opt_tag),
		       tag_class);
	    return 0;
	}
	return 1;
    }
    else {
	optional = options == Qnil ? Qnil : ossl_template_hash_get_optional(options);
	default_val = options == Qnil ? Qnil : ossl_template_hash_get_default(options);
	if (!(optional != Qnil || default_val != Qnil || force_optional)) {
	    if (name != Qnil) {
		StringValue(name);
		c_name = (char *)RSTRING_PTR(name);
	    }
	    else {
		c_name = "UNNAMED";
	    }

	    ossl_raise(eTemplateError, 
		       "Mandatory value %s could not be parsed. "
		       "Expected tag: %d Got: %d",
		       c_name, 
		       FIX2INT(tag_or_defaukt(opt_tag, type)),
		       tag);
	    return 0;
	}

	return 0;
    }
} 

static int
parse_primitive(VALUE obj, VALUE def, unsigned char **pp, long length, int tag, int tag_class)
{
    VALUE type, name, options;
    
    type = ossl_template_hash_get_type(def);
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);

    if (!match(tag, tag_class, type, name, options))
	return 0;

    /* TODO */

}

static int
int_ossl_template_parse(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    ID codec;
    unsigned char *start;
    long len;
    int hlen, tag, tc, j;
    int infinite;

    start = *pp;
    codec = SYM2ID(ossl_template_hash_get_codec(def));
    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);

    if ((j & 0x01) && (len == 0)) {
	if (!(j & V_ASN1_CONSTRUCTED)) {
	    ossl_raise(eTemplateError, "Infinite length for primitive value");
	}
	infinite = 1;
    }
    max_length -= hlen;
    
    if (len > max_length) ossl_raise(eTemplateError, "Value is too short");
    
    if (codec == sPRIMITIVE) {
	if (infinite) {
	    /* TODO */
	}
	else {
	    return parse_primitive(obj, def, &start, hlen + len, tag, tc);    
	}
    }
    else if (codec == sTEMPLATE) {
	/* return parse_template(obj, def, pp, max_length); */
    }
    else if (codec == sCONSTRUCTIVE) {
	/* return parse_constructive(obj, def, pp, max_length, offset); */    
    }
    else if (codec == sSEQUENCE_OF) {
	/* return parse_seq_of(obj, def, pp, max_length, offset); */    
    }
    else if (codec == sSET_OF) {
	/* return parse_set_of(obj, def, pp, max_length, offset); */    
    }
    else if (codec == sCHOICE) {
	/* return parse_choice(obj, def, pp, max_length, offset); */    
    }
    else {
    	ossl_raise(rb_eRuntimeError, 
		   "Unknown codec: %s", 
		   rb_sym_to_s(ossl_template_hash_get_codec(def)));
	return 0; /* dummy */
    }
}

static VALUE
ossl_template_parse(VALUE self, VALUE der)
{
    VALUE def, obj;
    unsigned char *p;
    long offset = 0;
    volatile VALUE tmp;


    if (NIL_P(der)) 
	rb_raise(rb_eArgError, "Cannot parse nil.");

    if (!(def = ossl_template_get_definition(self))) {	
	rb_raise(rb_eArgError, 
		"Class %s has no definition.",
	        rb_class2name(CLASS_OF(self)));
    }

    der = ossl_to_der_if_possible(der);
    obj = rb_obj_alloc(self);
    int_ossl_template_initialize(obj, Qnil, 1);
    tmp = rb_str_new4(StringValue(der));
    p = (unsigned char *)RSTRING_PTR(tmp);

    if (!int_ossl_template_parse(obj, def, &p, RSTRING_LEN(tmp))) {
	VALUE type = ossl_template_hash_get_type(def);
	ossl_raise(eTemplateError,
	           "Could not match type %s",
	           rb_class2name(type));
    }

    return obj;
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

    rb_scan_args(argc, argv, "01", &der);
    if (!NIL_P(der)) {
	def = ossl_template_get_definition(CLASS_OF(self));
	der = ossl_to_der_if_possible(der);
	tmp = rb_str_new4(StringValue(der));
	p = (unsigned char *)RSTRING_PTR(tmp);
	if (!int_ossl_template_parse(self, def, &p, RSTRING_LEN(tmp))) {
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

static void
int_ossl_template_initialize(VALUE self, VALUE options, int parse)
{
    VALUE def;

    def = ossl_template_get_definition(CLASS_OF(self));
    if (!NIL_P(options)) {
	rb_iv_set(self, "@options", options);
    }
    int_ossl_template_init_mandatory_and_defaults(self, def, parse);
}

static VALUE
int_ossl_template_init_mandatory_and_defaults_i(VALUE inner_def, VALUE args)
{
    VALUE options, optional, default_val, type, name;

    VALUE self = rb_ary_entry(args, 0);
    VALUE parse = rb_ary_entry(args, 1);

    options = ossl_template_hash_get_options(inner_def);
    default_val = ossl_template_hash_get_default(options);

    if (parse == Qfalse) {
	int mandatory = 1;
        if (options != Qnil) {
	    optional = ossl_template_hash_get_optional(options);
	    mandatory = !(optional == Qtrue || default_val != Qnil);
	}
	type = ossl_template_hash_get_type(inner_def);
	name = ossl_template_hash_get_name(inner_def);
	if (mandatory && 
	    name != Qnil &&
	    type != Qnil &&
	    rb_mod_include_p(type, mTemplate)) {

	    VALUE obj = rb_obj_alloc(type);
	    StringValue(name);
	    int_ossl_template_initialize(obj, options, 0);
	    rb_iv_set(self, RSTRING_PTR(name), obj);
	}
    }
    
    if (options != Qnil && default_val != Qnil && name != Qnil) {
	StringValue(name);
	rb_iv_set(self, RSTRING_PTR(name), default_val);
    }

    return Qnil;
}

static void
int_ossl_template_init_mandatory_and_defaults(VALUE self, VALUE def, int parse)
{
    VALUE inner_def, args;

    inner_def = ossl_template_hash_get_inner_def(def);
    args = rb_ary_new3(2, self, parse ? Qtrue : Qfalse);
    rb_block_call(inner_def, rb_intern("each"), 0, 0, int_ossl_template_init_mandatory_and_defaults_i, args);     
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

    mTemplate = rb_define_module_under(mASN1, "Template");
    mParser = rb_define_module_under(mTemplate, "Parser");
    eTemplateError = rb_define_class_under(mTemplate, "TemplateError", eOSSLError);

    rb_define_method(mTemplate, "initialize", ossl_template_initialize, -1);
    rb_define_method(mTemplate, "to_der", ossl_template_to_der, 0);
    
    rb_define_method(mParser, "parse", ossl_template_parse, 1);
}

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
#include "ossl_asn1-internal.h"

VALUE mTemplate;
VALUE mParser;
VALUE eTemplateError;

static ID sOPTIONS, sDEFAULT, sNAME, sTYPE, 
	  sOPTIONAL, sTAG, sTAGGING, sINNER_DEF,
	  sMIN_SIZE, sCODEC; 
	  
static ID sPRIMITIVE, sCONSTRUCTIVE, sTEMPLATE,
	  sSEQUENCE_OF, sSET_OF, sCHOICE;

static ID sIMPLICIT, sEXPLICIT;

#define ossl_template_get_definition(o)		rb_iv_get((o), "@definition")
#define ossl_template_get_options(o)		rb_iv_get((o), "@options")
#define ossl_template_set_options(o, v)		rb_iv_set((o), "@options", (v))
#define ossl_template_get_unused_bits(o)	rb_iv_get((o), "@unused_bits")
#define ossl_template_set_unused_bits(o, v)	rb_iv_set((o), "@unused_bits", (v))
#define ossl_template_get_infinite_length(o)	rb_iv_get((o), "@infinite_length")
#define ossl_template_set_infinite_length(o, v)	rb_iv_set((o), "@infinite_length", (v))

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

#define match(t, tc, et, etc, n, o)		match0((t), (tc), (et), (etc), (n), (o), 0) 
#define parse_seq_of(o, d, pp, l)		parse_constructive_of((o), (d), (pp), (l))
#define parse_set_of(o, d, pp, l)		parse_constructive_of((o), (d), (pp), (l))
#define is_optional(opts)			((opts) && \
         					 (ossl_template_hash_get_optional((opts)) == Qtrue || \
						 (ossl_template_hash_get_default((opts)) != Qnil)))
#define is_infinite_tag(j)			((j) & 0x01)
#define tag_or_default(tag, type)		((tag) == Qnil ? FIX2INT((type)) : FIX2INT((tag)))
#define determine_tag_class(tag)		((tag) == Qnil ? V_ASN1_UNIVERSAL : V_ASN1_CONTEXT_SPECIFIC)
#define get_c_name(name, c_name)		if (name != Qnil) { \
    						    StringValue(name); \
    						    *c_name = (const char *)RSTRING_PTR(name); \
    						} \
	    					else { \
						    *c_name = "UNNAMED"; \
						}

static void int_ossl_template_initialize(VALUE self, VALUE options, int parse);
static void  int_ossl_template_init_mandatory_and_defaults(VALUE self, VALUE def, int parse);
static int int_ossl_template_parse(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static int parse_eoc(unsigned char **pp, long *max_length);
static int parse_primitive(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static int parse_primitive_inf(VALUE obj, VALUE def, unsigned char **pp, long max_length, int tag);
static int parse_template(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static int parse_constructive(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static int parse_constructive_of(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static int parse_choice(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static int parse_tagged(unsigned char **pp, long *max_length, VALUE def, VALUE tagging, int *expect_eoc);
static int parse_tagged_explicit(unsigned char **pp, long *max_length, VALUE def, int *expect_eoc);
static int parse_tagged_implicit(unsigned char **pp, long *max_length, VALUE def);
static void parse_header(unsigned char **pp, long max_length, long *len, int *j, int *tag, int *tc, int *hlen);
static int match0(int tag, int tag_class, VALUE expected_tag, int expected_tc, VALUE name, VALUE options, int force_optional);
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

static void
parse_header(unsigned char **pp,
             long max_length, 
	     long *len,
	     int *j,
	     int *tag, 
	     int *tc,
	     int *hlen)
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
    
    if (is_infinite_tag(*j) && (*len == 0)) {
	if (!(*j & V_ASN1_CONSTRUCTED)) {
	    ossl_raise(eTemplateError, "Infinite length for primitive value");
	}
    }

    if (*len > (max_length - *hlen)) ossl_raise(eTemplateError, "Value is too short");
}

static int
parse_tagged(unsigned char **pp, long *max_length, VALUE def, VALUE tagging, int* expect_eoc)
{
    ID id_tagging;

    id_tagging = SYM2ID(tagging);
    if (id_tagging == sEXPLICIT) {
	return parse_tagged_explicit(pp, max_length, def, expect_eoc);
    }
    else if (id_tagging == sIMPLICIT) {
	return parse_tagged_implicit(pp, max_length, def);
    }
    else {
	ossl_raise(rb_eArgError,
		   "Unrecognized tagging: %s",
		   rb_sym_to_s(tagging));
	return 0;
    }
}

static int
parse_tagged_explicit(unsigned char **pp, long *max_length, VALUE def, int *expect_eoc)
{
    long len;
    int tag, tc, j, hlen;
    VALUE type, name, options, expected_tag;
    
    type = ossl_template_hash_get_type(def);
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);
    expected_tag = ossl_template_hash_get_tag(options);

    parse_header(pp, *max_length, &len, &j, &tag, &tc, &hlen);
    
    if (!match(tag, tc, expected_tag, V_ASN1_CONTEXT_SPECIFIC, name, options))
	return 0;

    *pp += hlen;
    *max_length -= hlen;
    *expect_eoc = is_infinite_tag(j) ? 1 : 0;
    return 1;
}

static int
parse_tagged_implicit(unsigned char **pp, long *max_length, VALUE def)
{
    long len, new_len;
    unsigned char *start;
    int tag, tc, j, hlen, new_tag, cons = 0;
    VALUE type, name, options, expected_tag;
    
    type = ossl_template_hash_get_type(def);
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);
    expected_tag = ossl_template_hash_get_tag(options);

    parse_header(pp, *max_length, &len, &j, &tag, &tc, &hlen);
    
    if (!match(tag, tc, expected_tag, V_ASN1_CONTEXT_SPECIFIC, name, options))
	return 0;
    if (j & V_ASN1_CONSTRUCTED)
	cons = 1;
    if (is_infinite_tag(j))
	cons = 2;
    new_tag = FIX2INT(expected_tag);
    if((new_len = ASN1_object_size(cons, len, new_tag)) <= 0)
	ossl_raise(eASN1Error, NULL);
    start = *pp;
    if (new_len == hlen + len) {
	ASN1_put_object(pp, cons, new_len, new_tag, V_ASN1_UNIVERSAL);
    }
    else {
	if (new_len < hlen + len) {
	    *pp += hlen + len - new_len;
	    ASN1_put_object(pp, cons, new_len, new_tag, V_ASN1_UNIVERSAL);
	}
	else {
    	    /* TODO */
	    rb_raise(rb_eRuntimeError, "Not supported yet");
	    return 0;
	}
    }
    *pp = start;
    return 1;
}

static int
match0(int tag,
       int tag_class, 
       VALUE expected_tag,
       int expected_tc,
       VALUE name,
       VALUE options, 
       int force_optional)
{
    const char *c_name;

    if (tag == FIX2INT(expected_tag)) {
	if (tag_class != expected_tc) { 
	    ossl_raise(eTemplateError,
		       "Tag class mismatch. Expected: %d"
		       "Got: %d",
		       expected_tc,
		       tag_class);
	    return 0;
	}
	return 1;
    }
    else {
    	if (!is_optional(options)) {
	  get_c_name(name, &c_name);
	  ossl_raise(eTemplateError, 
	       	     "Mandatory value %s could not be parsed. "
		     "Expected tag: %d Got: %d",
		     c_name, 
		     FIX2INT(expected_tag),
		     tag);
	    return 0;
	}
	return 0;
    }
}

static int
parse_eoc(unsigned char **pp, long *max_length)
{
    long len;
    int tag, tc, j, hlen;

    parse_header(pp, *max_length, &len, &j, &tag, &tc, &hlen);
    if (!(tag == V_ASN1_EOC && tc == V_ASN1_UNIVERSAL && len == 0))
	return 0;

    *pp += hlen;
    *max_length -= hlen;
    return 1;
}

static int
parse_primitive(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    unsigned char *start;
    const char *p;
    long len, flag = 0;
    int tag, tc, j, hlen, expected_tc;
    const char *c_name;

    VALUE type, name, options, value;
    
    type = ossl_template_hash_get_type(def);
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);

    start = *pp;
    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);
    
    printf("Primitive: Tag %d Len %ld j %d\n", tag, len, j);
    
    if (!is_infinite_tag(j) && (j & V_ASN1_CONSTRUCTED)) {
	get_c_name(name, &c_name);
	ossl_raise(eTemplateError, 
		   "Constructed bit set for primitive value %s",
		   c_name);
	goto rewind;
    }
    
    if (!match(tag, tc, type, V_ASN1_UNIVERSAL, name, options))
	goto rewind;

    if (is_infinite_tag(j))
	return parse_primitive_inf(obj, def, pp, max_length, tag);
    
    switch(tag) {
    case V_ASN1_BOOLEAN:
	value = decode_bool(start, hlen+len);
	break;
    case V_ASN1_INTEGER:
	value = decode_int(start, hlen+len);
	break;
    case V_ASN1_BIT_STRING:
	value = decode_bstr(start, hlen+len, &flag);
	ossl_template_set_unused_bits(value, LONG2NUM(flag));
	break;
    case V_ASN1_NULL:
	value = decode_null(start, hlen+len);
	break;
    case V_ASN1_ENUMERATED:
	value = decode_enum(start, hlen+len);
	break;
    case V_ASN1_OBJECT:
	value = decode_obj(start, hlen+len);
	break;
    case V_ASN1_UTCTIME:           /* FALLTHROUGH */
    case V_ASN1_GENERALIZEDTIME:
	value = decode_time(start, hlen+len);
	break;
    default:
	p = (const char *)start;
	value = rb_str_new(p, len);
	if (tag == V_ASN1_UTF8STRING) {
	    value = rb_funcall(value, rb_intern("force_encoding"), 1, rb_str_new2("UTF-8"));
	} 
	break;
    }

    *pp += hlen + len;
    if (tag != V_ASN1_NULL)
	rb_ivar_set(obj, SYM2ID(name), value);
    return 1;

rewind:

    *pp = start;
    return 0;
}

static int
parse_primitive_inf(VALUE obj, VALUE def, unsigned char **pp,  long max_length, int tag)
{
    /* TODO */
    return 0;
}

static int
parse_constructive(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    unsigned char *start, *start_seq;
    const char *p;
    long len, idef_size;
    int i, tag, tc, j, hlen, expected_tc, min_size, num_parsed = 0;
    const char *c_name;

    VALUE type, name, options, value, inner_def_ary, inner_def;
    
    type = ossl_template_hash_get_type(def);
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);

    start = *pp;
    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);
    printf("Constructive: Tag %d Len %ld j %d\n", tag, len, j);
    if (!(j & V_ASN1_CONSTRUCTED)) {
	get_c_name(name, &c_name);
	ossl_raise(eTemplateError, 
		   "Constructed bit not set for constructive value %s",
		   c_name);
	return 0;
    }
    
    if (!match(tag, tc, type, V_ASN1_UNIVERSAL, name, options))
	goto rewind;

    *pp += hlen;
    start_seq = *pp;
    max_length -= hlen;

    inner_def_ary = ossl_template_hash_get_inner_def(def);
    idef_size = RARRAY_LEN(inner_def_ary);

    for (i = 0; i < idef_size && max_length > 0; i++) {
	inner_def = rb_ary_entry(inner_def_ary, i);
	if (int_ossl_template_parse(obj, inner_def, pp, max_length)) {
	    num_parsed++;
	    max_length -= *pp - start_seq;
	}
    }

    /* check whether num_parsed is feasible */
    min_size = FIX2INT(ossl_template_hash_get_min_size(def));
    if (num_parsed < min_size) {
	ossl_raise(eTemplateError,
		   "Expected %d..%d values. Got %d",
		   min_size, idef_size, num_parsed);
	return 0;
    }

    if (is_infinite_tag(j)) {
       	if(!parse_eoc(pp, &max_length)) {
	    get_c_name(name, &c_name);
	    ossl_raise(eTemplateError,
		       "No closing EOC found for infinite constructed value %s",
		       c_name);
	    return 0;
	}
	ossl_template_set_infinite_length(obj, Qtrue);
    }

    return 1;

rewind:

    *pp = start;
    return 0;
}

static int
parse_template(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    const char *c_name;
    VALUE instance, type, type_def, options, name;

    type = ossl_template_hash_get_type(def);
    options = ossl_template_get_options(def);
    name = ossl_template_hash_get_name(def);
    instance = rb_obj_alloc(type);
    int_ossl_template_initialize(instance, Qnil, 1);
    type_def = ossl_template_get_definition(CLASS_OF(type));
    if (!int_ossl_template_parse(instance, type_def, pp, max_length)) {
	if (!is_optional(options)) {
	    get_c_name(name, &c_name);
	    ossl_raise(eTemplateError, 
	       	     "Mandatory template value %s could not be parsed. ",
		     c_name);
	    return 0;
	}
	return 0;
    }

    rb_ivar_set(obj, SYM2ID(name), instance);
    return 1;
}

static int
parse_constructive_of(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    unsigned char *start;
    long len;
    int tag, tc, j, hlen; 
    const char *c_name;

    VALUE type, name, options, val_ary;
    
    type = ossl_template_hash_get_type(def);
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);

    start = *pp;
    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);
    printf("ConstructiveOf: Tag %d Len %ld j %d\n", tag, len, j);
    if (!(j & V_ASN1_CONSTRUCTED)) {
	get_c_name(name, &c_name);
	ossl_raise(eTemplateError, 
		   "Constructed bit not set for ConstructiveOf value %s",
		   c_name);
	return 0;
    }
    
    if (!match(tag, tc, type, V_ASN1_UNIVERSAL, name, options))
	goto rewind;

    *pp += hlen;
    max_length -= hlen;

    if(rb_mod_include_p(type, mTemplate)) {
	val_ary = Qnil; /* TODO: parse templates */
    }
    else {
	val_ary = Qnil;/* TODO: parse primitives */
    }

    if (is_infinite_tag(j)) {
       	if(!parse_eoc(pp, &max_length)) {
	    get_c_name(name, &c_name);
	    ossl_raise(eTemplateError,
		       "No closing EOC found for infinite ConstructedOf value %s",
		       c_name);
	    return 0;
	}
	ossl_template_set_infinite_length(obj, Qtrue);
    }

    rb_ivar_set(obj, SYM2ID(name), val_ary);
    return 1;

rewind:

    *pp = start;
    return 0;
}

static int
parse_choice(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    return 0; /* TODO */
}

static int
int_ossl_template_parse(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    unsigned char *start, *start_unpacked;
    int ret = 0, expect_eoc = 0;
    VALUE type, options, tagging, name;
    ID codec;
    const char *c_name;
   
    start = *pp; 
    type = ossl_template_hash_get_type(def);
    options = ossl_template_hash_get_options(def);
    tagging = options == Qnil ? Qnil : ossl_template_hash_get_tagging(options);

    if (tagging != Qnil) {
    	if (!parse_tagged(pp, &max_length, def, tagging, &expect_eoc)) {
	    ret = 0;
	    goto rewind;
	}
    }
    
    start_unpacked = *pp;
    codec = SYM2ID(ossl_template_hash_get_codec(def));
        
    if (codec == sPRIMITIVE) {
	ret = parse_primitive(obj, def, pp, max_length);    
    }
    else if (codec == sTEMPLATE) {
	ret = parse_template(obj, def, pp, max_length);
    }
    else if (codec == sCONSTRUCTIVE) {
	ret = parse_constructive(obj, def, pp, max_length);    
    }
    else if (codec == sSEQUENCE_OF) {
	ret = parse_seq_of(obj, def, pp, max_length);    
    }
    else if (codec == sSET_OF) {
	ret = parse_set_of(obj, def, pp, max_length);    
    }
    else if (codec == sCHOICE) {
	ret = parse_choice(obj, def, pp, max_length);    
    }
    else {
    	ossl_raise(rb_eRuntimeError, 
		   "Unknown codec: %s", 
		   RSTRING_PTR(rb_sym_to_s(ossl_template_hash_get_codec(def))));
	return 0; /* dummy */
    }

    if (ret && expect_eoc) {
	max_length -= *pp - start_unpacked;
       	if (!parse_eoc(pp, &max_length)) {
	    name = ossl_template_hash_get_name(def);
	    get_c_name(name, &c_name);
	    ossl_raise(eTemplateError,
		   "No closing EOC found for infinite lenght explicitly tagged value %s",
		   c_name);
	    return 0;
	}
    }

rewind:

    if (!ret) {
	*pp = start;
    }

    return ret;
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
	ossl_template_set_options(self, options);
    }
    int_ossl_template_init_mandatory_and_defaults(self, def, parse);
}

static VALUE
int_ossl_template_init_mandatory_and_defaults_i(VALUE inner_def, VALUE args)
{
    VALUE options, optional, default_val = Qnil, type, name;

    VALUE self = rb_ary_entry(args, 0);
    VALUE parse = rb_ary_entry(args, 1);

    options = ossl_template_hash_get_options(inner_def);
    if (options != Qnil)
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

    sIMPLICIT = rb_intern("IMPLICIT");
    sEXPLICIT = rb_intern("EXPLICIT");

    mTemplate = rb_define_module_under(mASN1, "Template");
    mParser = rb_define_module_under(mTemplate, "Parser");
    eTemplateError = rb_define_class_under(mTemplate, "TemplateError", eOSSLError);

    rb_define_method(mTemplate, "initialize", ossl_template_initialize, -1);
    rb_define_method(mTemplate, "to_der", ossl_template_to_der, 0);
    
    rb_define_method(mParser, "parse", ossl_template_parse, 1);
}

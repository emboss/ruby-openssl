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
VALUE cChoiceValue;

static ID sOPTIONS, sDEFAULT, sNAME, sTYPE, 
	  sOPTIONAL, sTAG, sTAGGING, sINNER_DEF,
	  sMIN_SIZE, sCODEC; 
	  
static ID sPRIMITIVE, sCONSTRUCTIVE, sTEMPLATE,
	  sSEQUENCE_OF, sSET_OF, sCHOICE, sANY;

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
#define parse_seq_of(o, d, pp, l)		parse_constructive_of((o), (d), (pp), (l), V_ASN1_SEQUENCE)
#define parse_set_of(o, d, pp, l)		parse_constructive_of((o), (d), (pp), (l), V_ASN1_SET)
#define is_optional(opts)			((opts) != Qnil && \
         					 (ossl_template_hash_get_optional((opts)) == Qtrue || \
						 (ossl_template_hash_get_default((opts)) != Qnil)))
#define is_infinite_tag(j)			((j) & 0x01)
#define tag_or_default(tag, type)		((tag) == Qnil ? FIX2INT((type)) : FIX2INT((tag)))
#define determine_tag_class(tag)		((tag) == Qnil ? V_ASN1_UNIVERSAL : V_ASN1_CONTEXT_SPECIFIC)
#define get_c_name(name, c_name)		if (name != Qnil) { \
    						    *c_name = (const char *)RSTRING_PTR(rb_sym_to_s(name)); \
    						} \
	    					else { \
						    *c_name = "UNNAMED"; \
						}

static void int_ossl_template_initialize(VALUE self, VALUE options, int parse);
static void int_ossl_template_init_mandatory_and_defaults(VALUE self, VALUE def, int parse);
static void int_ossl_template_init_mandatory_and_defaults_i(VALUE inner_def, VALUE self, int parse);
static long int_ossl_template_parse(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static int parse_eoc(unsigned char **pp, long max_length);
static long parse_primitive(VALUE obj, VALUE def, unsigned char **pp, long max_length, VALUE *ret_val);
static long parse_primitive_inf(VALUE obj, VALUE def, unsigned char **pp, long max_length, int tag, VALUE *ret_val);
static long parse_template(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static long parse_constructive(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static long parse_constructive_of(VALUE obj, VALUE def, unsigned char **pp, long max_length, int seq_or_set);
static VALUE parse_cons_of_templates(VALUE type, unsigned char **pp, long max_length, int is_infinite, long *read);
static VALUE parse_cons_of_prim(VALUE type, unsigned char **pp, long max_length, int is_infinite, long *read);
static long parse_choice(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static VALUE match_inner_def(int tag, int tc, VALUE def);
static long parse_any(VALUE obj, VALUE def, unsigned char **pp, long max_length);
static int parse_tagged_explicit(unsigned char **pp, long max_length, VALUE def, int *expect_eoc, int *read);
static int parse_tagged_implicit(unsigned char **pp, long max_length, VALUE def, unsigned char **untagged);
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
parse_tagged_explicit(unsigned char **pp, long max_length, VALUE def, int *expect_eoc, int *read)
{
    long len;
    int tag, tc, j, hlen;
    VALUE type, name, options, expected_tag;
    
    type = ossl_template_hash_get_type(def);
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);
    expected_tag = ossl_template_hash_get_tag(options);

    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);
    
    //printf("Explicit tagged: Tag %d Len %ld j %d max_len %ld\n", tag, len, j, max_length);

    if (!match(tag, tc, expected_tag, V_ASN1_CONTEXT_SPECIFIC, name, options))
	return 0;

    *pp += hlen;
    *read = hlen;
    *expect_eoc = is_infinite_tag(j) ? 1 : 0;
    return 1;
}

static int
parse_tagged_implicit(unsigned char **pp, long max_length, VALUE def, unsigned char **untagged)
{
    long len, new_len;
    unsigned char *p;
    int tag, tc, j, hlen, new_tag, cons = 0;
    VALUE type, name, options, expected_tag, type_def, codec, der;
    
    type = ossl_template_hash_get_type(def);
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);
    expected_tag = ossl_template_hash_get_tag(options);
    
    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);
    
    //printf("Implicit tagged: Tag %d Len %ld j %d max_len %ld\n", tag, len, j, max_length);

    if (!match(tag, tc, expected_tag, V_ASN1_CONTEXT_SPECIFIC, name, options))
	return 0;
    if (j & V_ASN1_CONSTRUCTED)
	cons = 1;
    if (is_infinite_tag(j))
	cons = 2;
    new_tag = FIX2INT(expected_tag);
    if((new_len = ASN1_object_size(cons, len, new_tag)) <= 0)
	ossl_raise(eASN1Error, NULL);

    *pp += hlen;

    codec = ossl_template_hash_get_codec(def);
    if (SYM2ID(codec) == sSEQUENCE_OF)
	new_tag = V_ASN1_SEQUENCE;
    else if (SYM2ID(codec) == sSET_OF)
	new_tag = V_ASN1_SET;
    else if (SYM2ID(codec) == sTEMPLATE) {
	type_def = ossl_template_get_definition(type);
	new_tag = FIX2INT(ossl_template_hash_get_type(type_def));
    }
    else if (SYM2ID(codec) == sPRIMITIVE || SYM2ID(codec) == sCONSTRUCTIVE)
	expected_tag = FIX2INT(type);
    else /* sANY */
	new_tag = tag;

    /* make a copy with rewritten header */
    p = (unsigned char *)OPENSSL_malloc(new_len);
    *untagged = p;
    ASN1_put_object(&p, cons, len, new_tag, V_ASN1_UNIVERSAL);
    memcpy(p, *pp, len);
    *pp += len;
   
    //printf("Rewrite: new_len %ld old_len %ld old tag: %d new tag: %d\n", new_len, hlen + len, tag, new_tag);
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
    	if (!is_optional(options) && !force_optional) {
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
parse_eoc(unsigned char **pp, long max_length)
{
    long len;
    int tag, tc, j, hlen;

    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);
    if (!(tag == V_ASN1_EOC && tc == V_ASN1_UNIVERSAL && len == 0))
	return 0;

    *pp += hlen;
    return hlen;
}

static long
parse_primitive(VALUE obj, VALUE def, unsigned char **pp, long max_length, VALUE *ret_val)
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
    
    if (!is_infinite_tag(j) && (j & V_ASN1_CONSTRUCTED)) {
	if (is_optional(options))
	    return 0;
	
	get_c_name(name, &c_name);
	ossl_raise(eTemplateError, 
		   "Constructed bit set for primitive value %s",
		   c_name);
	return 0;
    }
    
    //printf("Primitive: Tag %d Len %ld j %d max_len %ld\n", tag, len, j, max_length);

    if (!match(tag, tc, type, V_ASN1_UNIVERSAL, name, options))
	return 0;

    if (is_infinite_tag(j))
	return parse_primitive_inf(obj, def, pp, max_length, tag, ret_val);
    
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
    if (tag != V_ASN1_NULL) {
	if (obj != Qnil) 
	    rb_ivar_set(obj, SYM2ID(name), value);
	if (ret_val)
	    *ret_val = value;
    }
    return hlen + len;
}

static long
parse_primitive_inf(VALUE obj, VALUE def, unsigned char **pp,  long max_length, int tag, VALUE *ret_val)
{
    /* TODO */
    return 0;
}

static long
parse_constructive(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    unsigned char *start, *start_seq;
    const char *p;
    long len, idef_size, ret = 0, single_ret = 0;
    int i, tag, tc, j, hlen = 0, expected_tc, min_size, num_parsed = 0;
    int eoc_ret = 0;
    const char *c_name;

    VALUE type, name, options, value, inner_def_ary, inner_def;
    
    type = ossl_template_hash_get_type(def);
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);

    start = *pp;
    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);
    //printf("Constructive: Tag %d Len %ld j %d\n", tag, len, j);
    if (!(j & V_ASN1_CONSTRUCTED)) {
	if (is_optional(options))
	    return 0;
	
	get_c_name(name, &c_name);
	ossl_raise(eTemplateError, 
		   "Constructed bit not set for constructive value %s",
		   c_name);
	return 0;
    }
    
    if (!match(tag, tc, type, V_ASN1_UNIVERSAL, name, options))
	return 0;

    *pp += hlen;
    start_seq = *pp;
    max_length -= hlen;

    inner_def_ary = ossl_template_hash_get_inner_def(def);
    idef_size = RARRAY_LEN(inner_def_ary);

    for (i = 0; i < idef_size && max_length > 0; i++) {
	inner_def = rb_ary_entry(inner_def_ary, i);
	if ((single_ret = int_ossl_template_parse(obj, inner_def, pp, max_length))) {
	    num_parsed++;
	    max_length -= single_ret;
	    ret += single_ret;
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
       	if(!(eoc_ret = parse_eoc(pp, max_length))) {
	    get_c_name(name, &c_name);
	    ossl_raise(eTemplateError,
		       "No closing EOC found for infinite constructed value %s",
		       c_name);
	    return 0;
	}
	ossl_template_set_infinite_length(obj, Qtrue);
    }

    return hlen + ret + eoc_ret;
}

static long
parse_template(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    const char *c_name;
    long ret;
    VALUE instance, type, type_def, options, name;

    //printf("Template\n");

    type = ossl_template_hash_get_type(def);
    options = ossl_template_get_options(def);
    name = ossl_template_hash_get_name(def);
    instance = rb_obj_alloc(type);
    int_ossl_template_initialize(instance, Qnil, 1);
    type_def = ossl_template_get_definition(type);
    if (!(ret = int_ossl_template_parse(instance, type_def, pp, max_length))) {
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
    return ret;
}

static long
parse_constructive_of(VALUE obj, VALUE def, unsigned char **pp, long max_length, int seq_or_set)
{
    unsigned char *start;
    long len, tag_ret = 0, ret = 0, eoc_ret = 0;
    int tag, tc, j, hlen; 
    const char *c_name;

    VALUE type, name, options, val_ary;
    
    type = ossl_template_hash_get_type(def);
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);

    start = *pp;
    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);
    //printf("ConstructiveOf: Tag %d Len %ld j %d\n", tag, len, j);
    if (!(j & V_ASN1_CONSTRUCTED)) {
	get_c_name(name, &c_name);
	ossl_raise(eTemplateError, 
		   "Constructed bit not set for ConstructiveOf value %s",
		   c_name);
	return 0;
    }

    if (!match(tag, tc, INT2FIX(seq_or_set), V_ASN1_UNIVERSAL, name, options))
	return 0;

    *pp += hlen;
    max_length -= hlen;
    tag_ret = hlen;

    if(rb_mod_include_p(type, mTemplate)) {
	val_ary = parse_cons_of_templates(type, pp, len, is_infinite_tag(j), &ret);
    }
    else {
	val_ary = parse_cons_of_prim(type, pp, len, is_infinite_tag(j), &ret);
    }

    if (is_infinite_tag(j)) {
       	if(!(eoc_ret = parse_eoc(pp, max_length))) {
	    get_c_name(name, &c_name);
	    ossl_raise(eTemplateError,
		       "No closing EOC found for infinite ConstructedOf value %s",
		       c_name);
	    return 0;
	}
	ossl_template_set_infinite_length(obj, Qtrue);
    }

    if (RARRAY_LEN(val_ary) == 0 && !is_optional(options)) {
	get_c_name(name, &c_name);
	ossl_raise(eTemplateError, 
	 	   "Mandatory value %s could not be parsed. Sequence is empty",
		   c_name);
	return 0;
    }

    rb_ivar_set(obj, SYM2ID(name), val_ary);
    //printf("Constructive Of total read %ld\n", tag_ret + ret + eoc_ret);
    return tag_ret + ret + eoc_ret;
}

static VALUE
parse_cons_of_templates(VALUE type, unsigned char **pp, long max_length, int is_infinite, long *read)
{
    unsigned char *offset;
    long t_read = 0;
    VALUE val_ary = rb_ary_new();
    VALUE instance, type_def;

    type_def = ossl_template_get_definition(type);

    while (max_length > 0 || is_infinite) {
	offset = *pp;

    	if (parse_eoc(pp, max_length)) {
	    *pp = offset;
	    return val_ary;
	}

	//printf("ConstructiveOf Template max_len: %ld\n", max_length);
	instance = rb_obj_alloc(type);
	int_ossl_template_initialize(instance, Qnil, 1);
	if (!(t_read = int_ossl_template_parse(instance, type_def, pp, max_length))) {
	    ossl_raise(eTemplateError,
		       "Parsing template of type %s failed",
		       rb_class2name(type));
	    return Qnil;
	}
	//printf("Template of read: %ld max_len: %ld\n", t_read, max_length);
	rb_ary_push(val_ary, instance);
	max_length -= t_read;
	*read += t_read;
    }
    //printf("Exit template of loop");
    return val_ary;
}

static VALUE 
parse_cons_of_prim(VALUE type, unsigned char **pp, long max_length, int is_infinite, long *read) 
{
    unsigned char *offset;
    long p_read;
    VALUE val_ary = rb_ary_new();
    VALUE type_def, prim;

    type_def = rb_hash_new();
    rb_hash_aset(type_def, ID2SYM(sTYPE), type);
    rb_hash_aset(type_def, ID2SYM(sCODEC), ID2SYM(sPRIMITIVE));

    while (max_length > 0 || is_infinite) {
	offset = *pp;

    	if (parse_eoc(pp, max_length)) {
	    *pp = offset;
	    return val_ary;
	}

	//printf("ConstructiveOf Primitive\n");
	if (!(p_read = parse_primitive(Qnil, type_def, pp, max_length, &prim))) {
	    ossl_raise(eTemplateError,
		       "ConstructiveOf: Parsing template of type %s failed",
		       rb_class2name(type));
	    return Qnil;
	}
	if (CLASS_OF(prim) != type) {
	    ossl_raise(eTemplateError,
		       "ConstructiveOf: Parsing Primitive of type %s failed. Got %s instead",
		       rb_class2name(type),
		       rb_class2name(CLASS_OF(prim)));
	    return Qnil;

	}
	rb_ary_push(val_ary, prim);
	max_length -= p_read;
	*read += p_read;
    }
    return val_ary;
}

static VALUE 
match_inner_def(int tag, int tc, VALUE def)
{
    int i, first_any;
    long idef_size;
    const char *c_name;
    VALUE inner_def_ary, inner_def, type,
	  type_def, real_type,
	  options, name, codec, rtag;

    inner_def_ary = ossl_template_hash_get_inner_def(def);
    if (inner_def_ary == Qnil) {
	ossl_raise(eTemplateError, "Choice with no inner_def");
	return Qnil;
    }
    name = ossl_template_hash_get_name(def);

    idef_size = RARRAY_LEN(inner_def_ary);
    for (i = 0; i < idef_size; i++) {
	inner_def = rb_ary_entry(inner_def_ary, i);
	type = ossl_template_hash_get_type(inner_def);
	options = ossl_template_hash_get_options(inner_def);
	codec = ossl_template_hash_get_codec(inner_def);
	if (SYM2ID(codec) == sANY) {
	    rtag = options == Qnil ? Qnil : ossl_template_hash_get_tag(options);
	    if (rtag != Qnil && match0(tag, tc, rtag, V_ASN1_CONTEXT_SPECIFIC, name, options, 1)) 
		return inner_def;
	    else
		first_any = i;
	}
	else {
	    if (TYPE(type) == T_CLASS && rb_mod_include_p(type, mTemplate)) {
		type_def = ossl_template_get_definition(type);
		real_type = ossl_template_hash_get_type(type_def);
	    }
	    else {
		real_type = type;
	    }
	    if (match0(tag, tc, real_type, V_ASN1_UNIVERSAL, name, options, 1)) {
		return inner_def;
	    }
	}
    }

    if (first_any != -1) 
	return rb_ary_entry(inner_def_ary, first_any);

    options = ossl_template_get_options(def);

    if (!is_optional(options)) {
	get_c_name(name, &c_name);
	ossl_raise(eTemplateError,
		   "Mandatory choice value %s not found",
		   c_name);
	return Qnil;
    }

    return Qnil;
}
    
static long
parse_choice(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    unsigned char *start;
    long len, ret;
    int tag, tc, j, hlen; 
    const char *c_name;
    VALUE name, matching_def, choice_val, options;
    
    name = ossl_template_hash_get_name(def);

    start = *pp;
    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);
    //printf("Choice: Tag %d Len %ld j %d\n", tag, len, j);
    
    matching_def = match_inner_def(tag, tc, def);
    if (matching_def == Qnil)
	return 0;

    /* Produce a copy */
    matching_def = rb_funcall(matching_def, rb_intern("merge"), 1, rb_hash_new());
    rb_hash_aset(matching_def, ID2SYM(sNAME), ID2SYM(rb_intern("@value")));
    options = ossl_template_hash_get_options(matching_def);
    choice_val = rb_funcall(cChoiceValue,
	    		    rb_intern("new"), 
			    3,
			    ossl_template_hash_get_type(matching_def),
			    Qnil,
			    options == Qnil ? Qnil : ossl_template_hash_get_tag(options)); 

    if (!(ret = int_ossl_template_parse(choice_val, matching_def, pp, max_length))) {
	get_c_name(name, &c_name);
	ossl_raise(eTemplateError,
		   "Could not parse matching choice value of %s",
		   c_name);
	return 0;
    }
    rb_ivar_set(obj, SYM2ID(name), choice_val);
    return ret;
}

static long
parse_any(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    unsigned char *start;
    long len;
    int tag, tc, j, hlen; 
    const char *p;

    VALUE rtag, name, options, value;
    
    name = ossl_template_hash_get_name(def);
    options = ossl_template_hash_get_options(def);

    start = *pp;
    parse_header(pp, max_length, &len, &j, &tag, &tc, &hlen);
    //printf("Any: Tag %d Len %ld j %d\n", tag, len, j);
    
    if (is_optional(options)) {
	rtag = ossl_template_hash_get_tag(options); 
	if (rtag != Qnil) {
	    if (!match(tag, tc, rtag, tc, name, options)) {
		*pp = start;
		return 0;
	    }
	}
	else {
	    ossl_raise(eTemplateError, "Cannot unambiguously assign ANY value");
	    return 0;
	}
    }
    
    p = (const char *)start;
    value = rb_funcall(mASN1, rb_intern("decode"), 1, rb_str_new(p, hlen + len)); 
    rb_ivar_set(obj, SYM2ID(name), value);
    *pp += hlen + len;
    return hlen + len;
}

static long
int_ossl_template_parse(VALUE obj, VALUE def, unsigned char **pp, long max_length)
{
    unsigned char *start, *untagged = NULL, *original = NULL;
    long ret = 0, eoc_ret = 0;
    int expect_eoc = 0, tag_ret = 0;
    VALUE type, options, tagging, name;
    ID codec, id_tagging;
    const char *c_name;
   
    //printf("Inner parse\n");
    start = *pp; 
    type = ossl_template_hash_get_type(def);
    options = ossl_template_hash_get_options(def);
    tagging = options == Qnil ? Qnil : ossl_template_hash_get_tagging(options);
    codec = SYM2ID(ossl_template_hash_get_codec(def));


    /* Don't unpack tagging for choices, the info is needed when parsing them */
    if (tagging != Qnil && codec != sCHOICE) {
	id_tagging = SYM2ID(tagging);
	if (id_tagging == sEXPLICIT) {
	    if (!parse_tagged_explicit(pp, max_length, def, &expect_eoc, &tag_ret))
		goto rewind;
	}
	else {
	    if (!parse_tagged_implicit(pp, max_length, def, &untagged))
		goto rewind;
	    else {
		original = *pp;
		*pp = untagged;
	    }
	}
    }
    
    if (codec == sPRIMITIVE) {
	ret = parse_primitive(obj, def, pp, max_length - tag_ret, NULL);    
    }
    else if (codec == sTEMPLATE) {
	ret = parse_template(obj, def, pp, max_length - tag_ret);
    }
    else if (codec == sCONSTRUCTIVE) {
	ret = parse_constructive(obj, def, pp, max_length - tag_ret);    
    }
    else if (codec == sSEQUENCE_OF) {
	ret = parse_seq_of(obj, def, pp, max_length - tag_ret);    
    }
    else if (codec == sSET_OF) {
	ret = parse_set_of(obj, def, pp, max_length - tag_ret);    
    }
    else if (codec == sCHOICE) {
	ret = parse_choice(obj, def, pp, max_length - tag_ret);    
    }
    else if (codec == sANY) {
	ret = parse_any(obj, def, pp, max_length - tag_ret);
    }
    else {
    	ossl_raise(rb_eRuntimeError, 
		   "Unknown codec: %s", 
		   RSTRING_PTR(rb_sym_to_s(ossl_template_hash_get_codec(def))));
	return 0; /* dummy */
    }

    if (tag_ret && expect_eoc) {
       	if (!(eoc_ret = parse_eoc(pp, max_length))) {
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
	return 0;
    }
    if (original) {
	*pp = original;
    }
    if (untagged) {
	OPENSSL_free(untagged);
    }
    //printf("Read: %ld\n", ret + tag_ret + eoc_ret);
    return ret + tag_ret + eoc_ret;
}

static VALUE
ossl_template_parse(VALUE self, VALUE der)
{
    VALUE def, obj;
    unsigned char *p;
    long max_length, read;
    volatile VALUE tmp;

    //printf("Top level parse.\n");

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
    max_length = RSTRING_LEN(tmp);

    if (!(read = int_ossl_template_parse(obj, def, &p, max_length))) {
	VALUE type = ossl_template_hash_get_type(def);
	ossl_raise(eTemplateError,
	           "Could not match type %s",
	           rb_class2name(type));
    }

    if (read != max_length) {
	ossl_raise(eTemplateError,
		   "Type mismatch. Bytes read: %ld Bytes available: %ld",
		   read, max_length);
	return Qnil;
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

    //printf("Top level init\n");

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
	mandatory = !is_optional(options);
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

    mTemplate = rb_define_module_under(mASN1, "Template");
    mParser = rb_define_module_under(mTemplate, "Parser");
    eTemplateError = rb_define_class_under(mTemplate, "TemplateError", eOSSLError);

    /* implementation is in template.rb */
    cChoiceValue = rb_define_class_under(mTemplate, "ChoiceValue", rb_cObject);

    rb_define_method(mTemplate, "initialize", ossl_template_initialize, -1);
    rb_define_method(mTemplate, "to_der", ossl_template_to_der, 0);
    
    rb_define_method(mParser, "parse", ossl_template_parse, 1);
}

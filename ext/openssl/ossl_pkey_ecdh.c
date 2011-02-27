/*
 * $Id$
 * Ruby implementation of ECDH
 * Copyright (C) 2011 Martin Boßlet <Martin.Bosslet@googlemail.com>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */

#include "ossl.h"
#include <string.h>

#if !defined(OPENSSL_NO_EC) && (OPENSSL_VERSION_NUMBER >= 0x0090802fL)

VALUE eECDHError;
VALUE cECDH;

#define Get_EC(obj) rb_iv_get((obj), "@key")
#define Set_EC(obj, ec) rb_iv_set((obj), "@key", (ec))

typedef struct {
	EC_POINT *point;
	int dont_free;
} ossl_ec_point;

#define GetPKeyEC(obj, pkey) do { \
    GetPKey(obj, pkey); \
    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_EC) { \
	ossl_raise(rb_eRuntimeError, "THIS IS NOT A EC PKEY!"); \
    } \
} while (0)

#define Get_EC_KEY(obj, key) do { \
    EVP_PKEY *pkey; \
    GetPKeyEC(obj, pkey); \
    key = pkey->pkey.ec; \
} while(0)

#define Require_EC_KEY(obj, key) do { \
    Get_EC_KEY(obj, key); \
    if (key == NULL) \
        rb_raise(eECError, "EC_KEY is not initialized"); \
} while(0)

#define SafeRequire_EC_KEY(obj, key) do { \
    OSSL_Check_Kind(obj, cEC); \
    Require_EC_KEY(obj, key); \
} while (0)

#define Get_EC_POINT(obj, p) do { \
    ossl_ec_point *ec_point; \
    Data_Get_Struct(obj, ossl_ec_point, ec_point); \
    if (ec_point == NULL) \
        rb_raise(eEC_POINT, "missing ossl_ec_point structure"); \
    p = ec_point->point; \
} while(0)

#define Require_EC_POINT(obj, point) do { \
    Get_EC_POINT(obj, point); \
    if (point == NULL) \
        rb_raise(eEC_POINT, "EC_POINT is not initialized"); \
} while(0)

#define SafeRequire_EC_POINT(obj, point) do { \
    OSSL_Check_Kind(obj, cEC_POINT); \
    Require_EC_POINT(obj, point); \
} while(0)

static VALUE
ossl_ecdh_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE ec;

    ec = rb_funcall2(cEC, rb_intern("new"), argc, argv);
    if (!rb_funcall(ec, rb_intern("public_key?"), 0) &&
            !rb_funcall(ec, rb_intern("private_key?"), 0)) {
        rb_funcall(ec, rb_intern("generate_key"), 0);
    }
    else {
        if (!rb_funcall(ec, rb_intern("private_key?"), 0)) {
            ossl_raise(eECDHError, "Cannot create an ECDH with a public key.");
        }
    }

    Set_EC(self, ec);

    return self;
}

/*
 *  call-seq:
 *     ecdh.generate_key -> self
 *
 */
static VALUE
ossl_ecdh_generate_key(VALUE self)
{
    VALUE ec, group;

    group = rb_iv_get(Get_EC(self), "@group");
    ec = rb_funcall(cEC, rb_intern("new"), 0);
    rb_funcall(ec, rb_intern("group="), 1, group);
    rb_funcall(ec, rb_intern("generate_key"), 0);
    Set_EC(self, ec);
    
    return self;
}

static VALUE
ossl_ecdh_to_pem(int argc, VALUE *argv, VALUE self) {
    return rb_funcall2(Get_EC(self), rb_intern("to_pem"), argc, argv);
}

static VALUE
ossl_ecdh_to_der(VALUE self) {
    return rb_funcall(Get_EC(self), rb_intern("to_der"), 0);
}

static VALUE
ossl_ecdh_to_text(VALUE self) {
    return rb_funcall(Get_EC(self), rb_intern("to_text"), 0);
}

static VALUE
ossl_ecdh_get_public_key(VALUE self) {
    return rb_funcall(Get_EC(self), rb_intern("public_key"), 0);
}

static VALUE
ossl_ecdh_get_group(VALUE self) {
    return rb_funcall(Get_EC(self), rb_intern("group"), 0);
}

static VALUE
ossl_ecdh_ansi_x963_kdf(VALUE shared_secret, VALUE size) {
    int isize, iterations, i, min_length, outsize;
    const unsigned char *secret;
    unsigned char *round_input;
    unsigned char *out;
    int counter = 0;
    VALUE retval;

    isize = NUM2INT(size);
    if (isize <= 0)
        ossl_raise(rb_eArgError, "Requested key length must be positive");
    secret = RSTRING_PTR(shared_secret);
    iterations = isize / SHA_DIGEST_LENGTH + 1;

    if (!(round_input = OPENSSL_malloc(sizeof(unsigned char *) * RSTRING_LEN(shared_secret) + sizeof(int) + 1)))
        ossl_raise(eECDHError, NULL);

    min_length = isize < SHA_DIGEST_LENGTH ? SHA_DIGEST_LENGTH : isize;
    outsize = sizeof(unsigned char *) * iterations * min_length + 1;
    if (!(out = OPENSSL_malloc(outsize))) {
        OPENSSL_free(round_input);
        ossl_raise(eECDHError, NULL);
    }

    for (i = 0; i < iterations; i++) {
        strcat(round_input, secret);
        strcat(round_input, (char*)((counter >> 3) & 0xFF));
        strcat(round_input, (char*)((counter >> 2) & 0xFF));
        strcat(round_input, (char*)((counter >> 1) & 0xFF));
        strcat(round_input, (char*)(counter & 0xFF));
        SHA1(round_input, strlen(round_input), out);
        out += SHA_DIGEST_LENGTH;
        counter++;
    }
    
    OPENSSL_free(round_input);
    retval = rb_str_new(out, outsize);
    OPENSSL_free(out);
    return retval;
}

static VALUE
ossl_ecdh_kdf_cb(VALUE shared_secret, VALUE size) {
    VALUE ary;

    ary = rb_ary_new2(2);
    rb_ary_store(ary, 0, shared_secret);
    rb_ary_store(ary, 1, size);

    return rb_yield(ary);
}
/*
 *  call-seq:
 *     ecdh.compute_key(pub_ec [, size]) -> string
 *
 *  === Parameters
 *  * +pub_ec+ is the public OpenSSL::PKey::EC instance of the key agreement peer.
 *  * +size+ is a Fixnum representing the desired output length - e.g. if you'd
 *           like to compute a symmetric key for AES 128, you'd specify size as
 *           128. If not provided, the output size will be equal to the hash
 *           function used in the KDF.
 *  
 *  Returns aString containing a shared secret computed from the other party's
 *  public EC key by the default key derivation function (or KDF). The default
 *  KDF used is the "ANSI X9.63 Key Derivation Function" (cf. "SEC 1: Elliptic
 *  Curve Cryptography.", ch. 3.6.1).
 *  To use a different KDF you may also provide a block that takes a two
 *  arguments (the initial shared secret, and the desired key length) and
 *  returns the final value of the computed key.
 *
 * === Example
 *
 * symm_key = ec.compute_key(pub_ec, 128) do |shared_secret, size|
 *   key = OpenSSL::Digest::SHA1.digest(shared_secret)
 *   key[0..size]
 * end
 *
 *
 */
static VALUE
ossl_ecdh_compute_key(int argc, VALUE *argv, VALUE self) {
    VALUE pub_ec, size;

    rb_scan_args(argc, argv, "11", &pub_ec, &size);

    EC_KEY *ec;
    EC_POINT *point;
    int buf_len;
    VALUE str;

    Require_EC_KEY(Get_EC(self), ec);
    SafeRequire_EC_POINT(pub_ec, point);


    /* TODO: find a way to dynamically determine the maximum string size with
             the help of the group */
    buf_len = 1024;
    str = rb_str_new(0, buf_len);
    buf_len = ECDH_compute_key(RSTRING_PTR(str), buf_len, point, ec, NULL);
    if (buf_len < 0)
         ossl_raise(eECError, "ECDH_compute_key failed");

    rb_str_resize(str, buf_len);

    return rb_block_given_p() ?
           ossl_ecdh_kdf_cb(str, size) :
           ossl_ecdh_ansi_x963_kdf(str, size);
}


/*
 * INIT
 */
void
Init_ossl_ecdh()
{
#if 0
    mOSSL = rb_define_module("OpenSSL"); /* let rdoc know about mOSSL and mPKey */
    mPKey = rb_define_module_under(mOSSL, "PKey");
#endif

    eECDHError = rb_define_class_under(mPKey, "ECDHError", ePKeyError);
    cECDH = rb_define_class_under(mPKey, "ECDH", rb_cObject);

    rb_define_method(cECDH, "initialize", ossl_ecdh_initialize, -1);
    rb_define_method(cECDH, "to_text", ossl_ecdh_to_text, 0);
    rb_define_method(cECDH, "to_pem", ossl_ecdh_to_pem, -1);
    rb_define_alias(cECDH, "export", "to_pem");
    rb_define_alias(cECDH, "to_s", "to_pem");
    rb_define_method(cECDH, "to_der", ossl_ecdh_to_der, 0);
    rb_define_method(cECDH, "public_key", ossl_ecdh_get_public_key, 0);
    rb_define_method(cECDH, "generate_key!", ossl_ecdh_generate_key, 0);
    rb_define_method(cECDH, "compute_key", ossl_ecdh_compute_key, -1);
    rb_define_method(cECDH, "group", ossl_ecdh_get_group, 0);
}


#else/* defined NO_EC */
void Init_ossl_ecdh()
{
}
#endif /* NO_EC */

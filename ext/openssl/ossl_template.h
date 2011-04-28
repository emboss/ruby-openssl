/*
 * $Id: ossl_template.h$
 * Copyright (C) 2011 Martin Bosslet <Martin.Bosslet@googlemail.com>
 * All rights reserved.
 *
 *
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(_OSSL_ASN1_TEMPLATE_H_)
#define _OSSL_ASN1_TEMPLATE_H_

extern VALUE mASN1;
/*
 * ASN1 Template module
 */
extern VALUE mTemplate;
extern VALUE eTemplateError;

void Init_ossl_template(void);

#endif

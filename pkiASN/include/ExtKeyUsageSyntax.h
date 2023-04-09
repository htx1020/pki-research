/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PKIX1Implicit88"
 * 	found in "../rfc3280-PKIX1Implicit88.asn1"
 * 	`asn1c -S ../../skeletons -pdu=Certificate -fcompound-names -fwide-types`
 */

#ifndef	_ExtKeyUsageSyntax_H_
#define	_ExtKeyUsageSyntax_H_


#include <asn_application.h>

/* Including external dependencies */
#include "KeyPurposeId.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ExtKeyUsageSyntax */
typedef struct ExtKeyUsageSyntax {
	A_SEQUENCE_OF(KeyPurposeId_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ExtKeyUsageSyntax_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ExtKeyUsageSyntax;

#ifdef __cplusplus
}
#endif

#endif	/* _ExtKeyUsageSyntax_H_ */
#include <asn_internal.h>

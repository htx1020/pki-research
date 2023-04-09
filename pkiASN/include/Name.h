/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PKIX1Explicit88"
 * 	found in "../rfc3280-PKIX1Explicit88.asn1"
 * 	`asn1c -S ../../skeletons -pdu=Certificate -fcompound-names -fwide-types`
 */

#ifndef	_Name_H_
#define	_Name_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RDNSequence.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Name_PR {
	Name_PR_NOTHING,	/* No components present */
	Name_PR_rdnSequence
} Name_PR;

/* Name */
typedef struct Name {
	Name_PR present;
	union Name_u {
		RDNSequence_t	 rdnSequence;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Name_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Name;
extern asn_CHOICE_specifics_t asn_SPC_Name_specs_1;
extern asn_TYPE_member_t asn_MBR_Name_1[1];
extern asn_per_constraints_t asn_PER_type_Name_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Name_H_ */
#include <asn_internal.h>

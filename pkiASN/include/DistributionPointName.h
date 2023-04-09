/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PKIX1Implicit88"
 * 	found in "../rfc3280-PKIX1Implicit88.asn1"
 * 	`asn1c -S ../../skeletons -pdu=Certificate -fcompound-names -fwide-types`
 */

#ifndef	_DistributionPointName_H_
#define	_DistributionPointName_H_


#include <asn_application.h>

/* Including external dependencies */
#include "GeneralNames.h"
#include "RelativeDistinguishedName.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DistributionPointName_PR {
	DistributionPointName_PR_NOTHING,	/* No components present */
	DistributionPointName_PR_fullName,
	DistributionPointName_PR_nameRelativeToCRLIssuer
} DistributionPointName_PR;

/* DistributionPointName */
typedef struct DistributionPointName {
	DistributionPointName_PR present;
	union DistributionPointName_u {
		GeneralNames_t	 fullName;
		RelativeDistinguishedName_t	 nameRelativeToCRLIssuer;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DistributionPointName_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DistributionPointName;
extern asn_CHOICE_specifics_t asn_SPC_DistributionPointName_specs_1;
extern asn_TYPE_member_t asn_MBR_DistributionPointName_1[2];
extern asn_per_constraints_t asn_PER_type_DistributionPointName_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _DistributionPointName_H_ */
#include <asn_internal.h>

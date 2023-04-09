/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PKIX1Explicit88"
 * 	found in "../rfc3280-PKIX1Explicit88.asn1"
 * 	`asn1c -S ../../skeletons -pdu=Certificate -fcompound-names -fwide-types`
 */

#ifndef	_OrganizationalUnitName_H_
#define	_OrganizationalUnitName_H_


#include <asn_application.h>

/* Including external dependencies */
#include <PrintableString.h>

#ifdef __cplusplus
extern "C" {
#endif

/* OrganizationalUnitName */
typedef PrintableString_t	 OrganizationalUnitName_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_OrganizationalUnitName_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_OrganizationalUnitName;
asn_struct_free_f OrganizationalUnitName_free;
asn_struct_print_f OrganizationalUnitName_print;
asn_constr_check_f OrganizationalUnitName_constraint;
ber_type_decoder_f OrganizationalUnitName_decode_ber;
der_type_encoder_f OrganizationalUnitName_encode_der;
xer_type_decoder_f OrganizationalUnitName_decode_xer;
xer_type_encoder_f OrganizationalUnitName_encode_xer;
oer_type_decoder_f OrganizationalUnitName_decode_oer;
oer_type_encoder_f OrganizationalUnitName_encode_oer;
per_type_decoder_f OrganizationalUnitName_decode_uper;
per_type_encoder_f OrganizationalUnitName_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _OrganizationalUnitName_H_ */
#include <asn_internal.h>

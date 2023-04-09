#ifndef __ASN1_OP_OER_H__
#define __ASN1_OP_OER_H__

#include "Certificate.h"

int oerEncode(asn_TYPE_descriptor_t *p_descriptor, const void *ptr,
              unsigned char *p_buff, unsigned int buff_size,
              unsigned int *p_encode_len);
int oerDecode(asn_TYPE_descriptor_t *p_descriptor, const unsigned char *p_buff,
              unsigned int len, void **p_ptr);
int oerPtrFree(asn_TYPE_descriptor_t *p_descriptor, void *p_ptr);
int oerDisplay(asn_TYPE_descriptor_t *p_descriptor, const unsigned char *p_buff,
               unsigned int len);
int oerDecodeToFile(asn_TYPE_descriptor_t *p_descriptor,
                    const unsigned char *p_buff, unsigned int len,
                    const char *filename);

int derEncode(asn_TYPE_descriptor_t *p_descriptor, const void *ptr,
              unsigned char *p_buff, unsigned int buff_size,
              unsigned int *p_encode_len);
int derDecode(asn_TYPE_descriptor_t *p_descriptor, const unsigned char *p_buff,
              unsigned int len, void **p_ptr);

#endif

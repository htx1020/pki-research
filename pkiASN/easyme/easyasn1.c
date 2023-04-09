#include "easyasn1.h"
#include <stdio.h>
#include <time.h>

#define EN_LOG_PROCESS 1
#define ERR_INPUT_PARA -1
#define ERR_OER_DECODE -2
#define ERR_OER_ENCODE -3

///* OER encode & decode & free memory */
int oerEncode(asn_TYPE_descriptor_t *p_descriptor, const void *ptr,
              unsigned char *p_buff, unsigned int buff_size,
              unsigned int *p_encode_len) {
  asn_enc_rval_t retenc;
  asn_oer_constraints_t constraints;
  *p_encode_len = 0;
  if (NULL == ptr || NULL == p_descriptor) {
    return ERR_INPUT_PARA;
  }

  retenc =
      oer_encode_to_buffer(p_descriptor, &constraints, ptr, p_buff, buff_size);
  if (-1 == retenc.encoded) {
#if EN_LOG_PROCESS
    printf("%s %d  %s tbs_encode fail ret=%d (%s:%d)\n", __FILE__, __LINE__,
           p_descriptor->name, (int)retenc.encoded, retenc.failed_type->name,
           (int)retenc.failed_type->elements_count);
#endif
    return ERR_OER_ENCODE;
  } else {
    *p_encode_len = retenc.encoded;
    return 0;
  }
}

int oerDecode(asn_TYPE_descriptor_t *p_descriptor, const unsigned char *p_buff,
              unsigned int len,
              void **p_ptr) { // Caution: Segmentation fault (core
                              // dumped),Violation of rules;
  asn_codec_ctx_t *opt_codec_ctx = NULL;
  asn_dec_rval_t retdec;
  int ret = 0;

  *p_ptr = NULL;
  if (NULL == p_buff || NULL == p_descriptor) {
    return ERR_INPUT_PARA;
  }
  retdec = oer_decode(opt_codec_ctx, p_descriptor, (void **)p_ptr, p_buff, len);
  if (RC_OK != retdec.code) {
#if EN_LOG_PROCESS
    printf("%s %d %s decode fail, ret=%d\n", __FUNCTION__, __LINE__,
           p_descriptor->name, retdec.code);
#endif
    return ERR_OER_DECODE;
  } else {
    ret = 0;
  }
  return ret;
}

int oerPtrFree(asn_TYPE_descriptor_t *p_descriptor, void *p_ptr) {
  if (NULL != p_ptr) {
    ASN_STRUCT_FREE(*p_descriptor, p_ptr);
    // p_ptr = NULL;
    return 0;
  } else {
    return -1;
  }
}

int oerDisplay(asn_TYPE_descriptor_t *p_descriptor, const unsigned char *p_buff,
               unsigned int len) {
  int ret = 0;
  void *p_struct = NULL;
  ret = oerDecode(p_descriptor, p_buff, len, &p_struct);
  if (0 == ret) {
    asn_fprint(NULL, p_descriptor, p_struct);
  }
  if (NULL != p_struct) {
    oerPtrFree(p_descriptor, p_struct);
  }
  return ret;
}

int oerDecodeToFile(asn_TYPE_descriptor_t *p_descriptor,
                    const unsigned char *p_buff, unsigned int len,
                    const char *filename) {
  int ret = 0;
  void *p_struct = NULL;
  ret = oerDecode(p_descriptor, p_buff, len, &p_struct);
  if (0 == ret) {
    FILE *pFile = fopen(filename, "wb");
    asn_fprint(pFile, p_descriptor, p_struct);
    fclose(pFile);
  }
  if (NULL != p_struct) {
    oerPtrFree(p_descriptor, p_struct);
  }
  return ret;
}

int derEncode(asn_TYPE_descriptor_t *p_descriptor, const void *ptr,
              unsigned char *p_buff, unsigned int buff_size,
              unsigned int *p_encode_len) {
  asn_codec_ctx_t ctx; /* See asn_codecs.h */
  asn_enc_rval_t rval =
      asn_encode_to_buffer(&ctx, ATS_DER, p_descriptor, ptr, p_buff, buff_size);
  if (rval.encoded == -1) {
    printf("faild %s\n", rval.failed_type->name);
    return -1;
  }

  *p_encode_len = rval.encoded;
  return 0;
}

int derDecode(asn_TYPE_descriptor_t *p_descriptor, const unsigned char *p_buff,
              unsigned int len, void **p_ptr) {
  asn_dec_rval_t rval;
  rval = asn_decode(0, ATS_DER, p_descriptor, p_ptr, (char *)p_buff, len);
  if (rval.code == RC_OK) {
    // success
    // ASN_STRUCT_FREE(*p_descriptor, p_ptr);
  } else {
    // error
    return -1;
  }
  return 0;
}

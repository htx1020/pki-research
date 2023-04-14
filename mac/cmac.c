#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t uint8;

uint8_t calcCrc8(uint8_t *data, uint32_t len) {
    uint8_t crc = 0x00;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if ((crc & 0x80) != 0) {
                crc = (crc << 1) ^ 0x1D;
            } else {
                crc = (crc << 1);
            }
        }
    }
    return crc ^ 0x00;
}

int genAesCmac(const uint8_t key[16], const uint8_t *data, uint32_t len,
               uint8_t mac[16]) {

    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    CMAC_CTX *cmac_ctx = CMAC_CTX_new();
    if (!cmac_ctx) {
        printf("create error!\n");
        return -1;
    }
    if (!CMAC_Init(cmac_ctx, key, 16, cipher, 0)) {
        CMAC_CTX_free(cmac_ctx);
        printf("init error!\n");
        return -1;
    }
    if (!CMAC_Update(cmac_ctx, data, len)) {
        CMAC_CTX_free(cmac_ctx);
        printf("update error!\n");
        return -1;
    }
    size_t reslen;
    uint8_t res[128];
    if (!CMAC_Final(cmac_ctx, res, &reslen)) {
        printf("[DeriveKey(): OEMCrypto_ERROR_CMAC_FAILURE]\n");
        return -1;
    }
    memcpy(mac, res, 16);
    CMAC_CTX_free(cmac_ctx);
    return 0;
}

/**
 * @brief 将key_raw转换为key_auth,作为SecOC软件模块的认证密钥
 *
 * @param[in]   	in   			key_raw数据
 * @param[in]   	vin   			VIN号
 * @param[out]   	out   			计算后输出的key_auth数据
 */
void SecOC_Algorithm1(const uint8 *in, const uint8 *vin, uint8 *out) {
    if (in == NULL || vin == NULL || out == NULL) {
        return;
    }
    int i = 0;
    int j = 0;
    int i_list[10] = {6, 9, 7, 4, 8, 2, 0, 5, 1, 3};
    int *switch_i = &i_list[0];

    uint8 used_iv[16] = {0};
    uint8 used_k[16] = {0};
    uint8 used_sc[16] = {0};
    uint8 t = 0;

    while (1) {
        switch (*switch_i) {
        case 2:
            switch_i++;
            for (i = 0; i < 16; i++) {
                used_k[i] = used_iv[i] ^ used_sc[i];
            }
            break;
        case 3:
            switch_i++;
            for (i = 0; i < 16 - 1; i++) {
                if (used_sc[i] < used_sc[i + 1]) {
                    t = used_sc[i];
                    used_sc[i] = used_sc[i + 1];
                    used_sc[i + 1] = t;
                }
            }
            return;
        case 1:
            switch_i++;
            for (i = 0; i < 16; i++) {
                used_k[i] ^= in[i];
            }
            for (i = 0; i < j; i++) {
                if (out[i] % 2 == 1) {
                    used_sc[i] ^= used_k[i];
                }
            }
            break;
        case 7:
            switch_i++;
            for (i = 0; i < 16 - 1; i++) {
                if (used_sc[i] > used_sc[i + 1]) {
                    t = used_sc[i];
                    used_sc[i] = used_sc[i + 1];
                    used_sc[i + 1] = t;
                }
            }
            break;
        case 5:
            switch_i++;
            for (i = 0; i < j; i++) {
                if (used_iv[i] % 2 == 1) {
                    out[i] = in[i] ^ used_k[i];
                } else {
                    out[i] = in[i] ^ used_iv[i];
                }
            }
            break;
        case 9:
            switch_i++;
            for (i = 0; i < 16; i++) {
                used_k[i] = in[i] ^ vin[16 - i];
            }
            break;
        case 4:
            switch_i++;
            for (i = 0; i < 16; i++) {
                used_iv[i] = used_k[i] % (in[i] + i + 1);
            }
            break;
        case 0:
            switch_i++;
            for (i = 0; i < 16 - 1; i++) {
                if (used_k[i] & 0x1) {
                    t = used_iv[i];
                    used_iv[i] = used_iv[i + 1];
                    used_iv[i + 1] = t;
                }
            }
            break;
        case 6:
            switch_i++;
            for (i = 0; i < 16; i++) {
                used_sc[i] ^= vin[i + 1] + i;
            }
            j = i;
            break;
        case 8:
            switch_i++;
            for (i = 0; i < 16; i++) {
                used_sc[i] ^= in[i] + i;
            }
            break;
        }
    }
}
void hexdump(const char *title, const uint8_t *data, uint32_t len) {
    printf("%s len[%ld]data:\n", title, len);
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    uint8_t key_raw[] = {0xEA, 0xBF, 0x33, 0x86, 0x97, 0x41, 0xF4, 0x03,
                         0xCD, 0xB1, 0x5F, 0x35, 0xD9, 0x8B, 0xDF, 0x34};

    uint8_t vin[] = "LC6TCGC6670008028";
    uint8_t oridata[] = {0x04, 0x61, 0x00, 0x00, 0x01, 0x00, 0x01};

    hexdump("key raw", key_raw, sizeof(key_raw));
    hexdump("vin", vin, 17);
    hexdump("data", oridata, sizeof(oridata));

    uint8_t key[16];
    memset(key, 0, sizeof(key));
    SecOC_Algorithm1(key_raw, vin, key);
    hexdump("g-key", key, sizeof(key));

    uint8_t mac[16];
    memset(mac, 0, sizeof(mac));
    genAesCmac(key, oridata, sizeof(oridata), mac);
    hexdump("mac", mac, sizeof(mac));

    uint8_t data_arr[] = {0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t crc = calcCrc8(data_arr, sizeof(data_arr));
    printf("\nH:%X\n", crc);
    return 0;
}

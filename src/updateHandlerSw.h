#include "mbedtls/sha256.h"
#include "tss2_tpm2_types.h"

#define ALG_NULL 0x0010
#define ALG_SHA256 0x000B
#define ALG_KDF1_SP800_108 0x0022
#define KDF_LIMIT 8192

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

#define HASH_DATA(hashState, dInSize, dIn)              \
    ((hashState)->def->method.data)(&(hashState)->state, dIn, dInSize)


int deriveUpdateKey(uint16_t hashAlg, uint8_t *seed, size_t seedSize,
    uint8_t *label, size_t labelSize, uint8_t *context, size_t contextSize,
    uint32_t limit, uint32_t expectedKeySize, uint8_t *derivedKey);

int DRBG_Generate_Helper(uint16_t hashAlg, uint16_t kdf, uint8_t *seed, 
    size_t seedSize, uint8_t *label, size_t labelSize, uint8_t *context, 
    size_t contextSize, uint32_t limit, uint32_t expectedKeySize, 
    uint8_t *derivedKey);

// int CryptKDFa_Helper(TPM2_ALG_ID hashAlg, TPM2B_DATA *key, 
//     const TPM2B_DATA *label, const TPM2B_DATA *contextU, 
//     const TPM2B_DATA *contextV, UINT32 sizeInBits, BYTE *keyStream, 
//     UINT32 *counterInOut, UINT16 blocks);

int CryptKDFa_Helper(uint16_t hashAlg, uint8_t *key, size_t keySize, 
    uint8_t *label, size_t labelSize, uint8_t *contextU, size_t contextUSize, 
    uint8_t *contextV, size_t contextVSize, uint32_t sizeInBits, 
    uint8_t *keyStream, uint32_t *counterInOut, uint16_t blocks);

int CryptHmacStart_Helper(mbedtls_sha256_context *ctx, TPM2_ALG_ID hashAlg, 
    size_t *keySize, uint8_t *key);

int CryptHmacEnd_Helper(mbedtls_sha256_context *ctx, TPM2_ALG_ID hashAlg,
    UINT16 keySize, BYTE *key, size_t dOutSize, BYTE *dOut);

int createHMACOpenSSL(uint16_t hashAlg, uint8_t *key, size_t keySize, uint8_t *data, 
    size_t dataSize, uint8_t *outputMac, size_t *outputMacSize);

int createHMAC(uint16_t hashAlg, uint8_t *key, size_t keySize, uint8_t *data, 
    size_t dataSize, uint8_t *outputMac, size_t *outputMacSize);

int createHMACPolicySigned(uint16_t hashAlg, uint8_t *key, size_t keySize, 
    uint8_t *nonceTPM, size_t nonceTPMSize, uint32_t expiration, uint8_t *cpHashA, 
    size_t cpHashASize, uint8_t *policyRef, size_t policyRefSize,
    uint8_t *outputMac, size_t *outputMacSize);
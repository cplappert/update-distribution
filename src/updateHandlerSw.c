#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include "tss2_tpm2_types.h"
// #include "libTPMsHelper.h"
// #include "mbedtls/sha256.h"
#include "mbedtls/md.h"

#include "updateHandlerSw.h"

#ifndef BITS_TO_BYTES
#  define BITS_TO_BYTES(bits) (((bits) + 7) >> 3)
#endif

#define LOGMODULE kDFa
#include "util/log.h"

int rc;

int deriveUpdateKey(uint16_t hashAlg, uint8_t *seed, size_t seedSize,
    uint8_t *label, size_t labelSize, uint8_t *context, size_t contextSize,
    uint32_t limit, uint32_t expectedKeySize, uint8_t *derivedKey){

    rc = DRBG_Generate_Helper(hashAlg, ALG_KDF1_SP800_108, seed, seedSize, label,
        labelSize, context, contextSize, limit, expectedKeySize, derivedKey);
    if (rc != 0){
        printf("Error: DRBG_Generate_Helper\n");
        return 1;
    }

    return 0;
}

// DRBG_Generate (hash: 11, seed: 16, 0)
int DRBG_Generate_Helper(uint16_t hashAlg, uint16_t kdf, uint8_t *seed, 
    size_t seedSize, uint8_t *label, size_t labelSize, uint8_t *context, 
    size_t contextSize, uint32_t limit, uint32_t expectedKeySize, 
    uint8_t *derivedKey){

    /* Initialize variable for return values.*/
    rc = 0;

    /* 1. Set up the KDF for object generation
     * -> DRBG_InstantiateSeededKdf 
     */

    if (hashAlg != ALG_SHA256){
        printf("Error: DRBG_Generate_Helper: hashAlg not supported.\n");
        return 1;
    }
    size_t digestSize = TPM2_SHA256_DIGEST_SIZE;

    if(kdf != ALG_KDF1_SP800_108){
        printf("Error: DRBG_Generate_Helper: kdf not supported.\n");
        return 1;  
    }

    // TPM2B_DATA labelData;
    // labelData.size = label.size;
    // memcpy(labelData.buffer, label.buffer ,labelData.size);

    // TPM2B_DATA contextData;
    // contextData.size = context.size;
    // memcpy(contextData.buffer, context.buffer, contextData.size);

    uint32_t counter = 0;
    uint32_t bytesLeft = expectedKeySize;

    while (bytesLeft > 0){
        uint16_t blocks = (uint16_t)(bytesLeft / digestSize); // 1
        if (blocks > 0){
            uint16_t size = blocks * digestSize;

            rc = CryptKDFa_Helper(hashAlg, seed, seedSize, label, labelSize, 
                context, contextSize, NULL, 0, limit, derivedKey, &counter, blocks);
            LOG_TRACE("Generated %02x\n", rc);
            // reduce the size remaining to be moved and advance the pointer
            bytesLeft -= size;

            LOGBLOB_DEBUG(derivedKey, expectedKeySize, "derivedKeyTest1: ");

            derivedKey += size;
        }
    }

    // TPM2B_DATA knownHMACKey = {
    //     .size = 32,
    //     .buffer = { 
    //         0x7f, 0x34, 0xbb, 0xa2, 0x6c, 0x94, 0xf3, 0xcd, 0x1a, 0x65, 0x84, 
    //         0x1e, 0x33, 0x3, 0x17, 0x68, 0x2d, 0xfa, 0xb2, 0xc6, 0xae, 0x24, 
    //         0xec, 0xf2, 0xa9, 0xe1, 0xad, 0x1, 0x67, 0x1b, 0x80, 0xfd, 0x0
    //     }
    // };

    return 0;
}

/* 10.2.13.8.2  CryptKDFa_Helper() */
/* This function performs the key generation according to Part 1 of the TPM specification. */
/* This function returns the number of bytes generated which may be zero. */
/* The key and keyStream pointers are not allowed to be NULL. The other pointer values may be
   NULL. The value of sizeInBits must be no larger than (2^18)-1 = 256K bits (32385 bytes). */
/*     The once parameter is set to allow incremental generation of a large value. If this flag is
       TRUE, sizeInBits will be used in the HMAC computation but only one iteration of the KDF is
       performed. This would be used for XOR obfuscation so that the mask value can be generated in
       digest-sized chunks rather than having to be generated all at once in an arbitrarily large
       buffer and then XORed into the result. If once is TRUE, then sizeInBits must be a multiple of
       8. */
/*     Any error in the processing of this command is considered fatal. */
/*     Return Value Meaning */
/*     0    hash algorithm is not supported or is TPM_ALG_NULL */
/*     > 0  the number of bytes in the keyStream buffer */

// CryptKDFa
int CryptKDFa_Helper(
      uint16_t           hashAlg,       // IN: hash algorithm used in HMAC
      uint8_t           *key,           // IN: HMAC key
      size_t             keySize,       // IN: HMAC key
      uint8_t           *label,         // IN: a label for the KDF
      size_t             labelSize,     // IN: a label for the KDF
      uint8_t           *contextU,      // IN: context U
      size_t             contextUSize,  // IN: a label for the KDF
      uint8_t           *contextV,      // IN: context U
      size_t             contextVSize,  // IN: a label for the KDF
      uint32_t           sizeInBits,    // IN: size of generated key in bits
      uint8_t           *keyStream,     // OUT: key buffer
      uint32_t          *counterInOut,  // IN/OUT: caller may provide the iteration
      //     counter for incremental operations to
      //     avoid large intermediate buffers.
      uint16_t           blocks         // IN: If non-zero, this is the maximum number
      //     of blocks to be returned, regardless
      //     of sizeInBits
      )
{

    uint32_t                 counter = 0;       // counter value
    // INT16                    bytes;             // number of bytes to produce
    size_t                   bytes;             // number of bytes to produce
    uint16_t                 generated;         // number of bytes generated
    uint8_t                  *stream = keyStream;
    // HMAC_STATE               hState;
    uint16_t                 digestSize = TPM2_SHA256_DIGEST_SIZE; //CryptHashGetDigestSize(hashAlg);
    int i; int j;
    // pAssert(key != NULL && keyStream != NULL);
    // TEST(TPM_ALG_KDF1_SP800_108);
    
    if(digestSize == 0)
        return 0;
    
    if(counterInOut != NULL)
    counter = *counterInOut;

    uint8_t buffer32[sizeof(uint32_t)];
    size_t buffer32_size = 0;

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    
    // If the size of the request is larger than the numbers will handle,
    // it is a fatal error.
    // pAssert(((sizeInBits + 7) / 8) <= INT16_MAX);
    
    // The number of bytes to be generated is the smaller of the sizeInBits bytes or
    // the number of requested blocks. The number of blocks is the smaller of the
    // number requested or the number allowed by sizeInBits. A partial block is
    // a full block.
    bytes = (blocks > 0) ? blocks * digestSize : (uint16_t)BITS_TO_BYTES(sizeInBits);
    generated = bytes;
    
    // Generate required bytes
    for(; bytes > 0; bytes -= digestSize)
    {   
        counter++;
        // Start HMAC
        // if(CryptHmacStart(&hState, hashAlg, key->size, key->buffer) == 0)
        // return 0;
        if(CryptHmacStart_Helper(&ctx, hashAlg, &keySize, key) == 0){
            return 1;
        }
        // Adding counter
        // CryptDigestUpdateInt(&hState.hashState, 4, counter);
        unsigned char charCounterArray[sizeof(UINT32)];
        int i; int j;
        for (i = 0, j = 24; i < sizeof(UINT32); i++, j=j-8){
            charCounterArray[i] = counter << j;
        }

        LOG_TRACE("Add Counter");
        rc = mbedtls_sha256_update_ret(&ctx, charCounterArray, sizeof(UINT32));
        // rc = mbedtls_md_hmac_update(&ctx, charCounterArray, sizeof(UINT32));
        if (rc != 0) {
            printf("%s\n", "Error mbedtls_md_hmac_update counter");
            return 1;
        }

        // Adding label
        if (label != NULL) {
        // HASH_DATA(&hState.hashState, label->size, (BYTE *)label->buffer);
            LOG_TRACE("Add Label\n");
            rc = mbedtls_sha256_update_ret(&ctx, label, labelSize);
            // rc = mbedtls_md_hmac_update(&ctx, label->buffer, label->size);
            if(rc != 0) {
                printf("%s\n", "Error mbedtls_md_hmac_update label");
                return 1;
            }
        }
        // Add a null. SP108 is not very clear about when the 0 is needed but to
        // make this like the previous version that did not add an 0x00 after
        // a null-terminated string, this version will only add a null byte
        // if the label parameter did not end in a null byte, or if no label
        // is present.
        if((label == NULL)
           || (labelSize == 0)
           || (label[labelSize - 1] != 0)){
            int zeroSize = 1;
            uint8_t zero = 0x00;
            LOG_TRACE("Add Zero\n");
            rc = mbedtls_sha256_update_ret(&ctx, &zero, zeroSize);
            // rc = mbedtls_md_hmac_update(&ctx, &zero, zeroSize);
            if(rc != 0){
                printf("%s\n", "Error mbedtls_md_hmac_update zero");
                return 1;
            }
        }
        if(contextU != NULL){
            // HASH_DATA(&hState.hashState, contextU->size, contextU->buffer);
            LOG_TRACE("Add contextU\n");
            rc = mbedtls_sha256_update_ret(&ctx, contextU, 
                contextUSize);
            // rc = mbedtls_md_hmac_update(&ctx, contextU->buffer, 
            //     contextU->size);
            if(rc != 0){
                printf("%s\n", "Error mbedtls_md_hmac_update contextU");
                return 1;
            }
        }

        // Adding contextV
        if(contextV != NULL){
            // HASH_DATA(&hState.hashState, contextV->size, contextV->buffer);
            LOG_TRACE("Add contextV\n");
            rc = mbedtls_sha256_update_ret(&ctx, contextV, 
                contextVSize);
            // rc = mbedtls_md_hmac_update(&ctx, contextV->buffer, 
            //     contextV->size);
            if(rc != 0){
                printf("%s\n", "Error mbedtls_md_hmac_update contextV");
                return 1;
            }
        }

        // Adding size in bits
        // CryptDigestUpdateInt(&hState.hashState, 4, sizeInBits);
        int sizeInBitsSize = sizeof(UINT32);
        uint8_t sizeInBitsTest[sizeInBitsSize]; // 8192
        memset(sizeInBitsTest, 0x00, sizeInBitsSize);
        for (i = 0, j = 24; i < sizeInBitsSize; i++, j=j-8) {
            sizeInBitsTest[i] = (sizeInBits >> j);
        }

        LOG_TRACE("Add sizeInBits\n");
        rc = mbedtls_sha256_update_ret(&ctx, sizeInBitsTest, sizeInBitsSize);
        // rc = mbedtls_md_hmac_update(&ctx, sizeInBitsTest, sizeInBitsSize);
        if(rc != 0){
            printf("%s\n", "Error mbedtls_md_hmac_update sizeInBits");
            return 1;
        }

        LOGBLOB_DEBUG(key, keySize, "Key");

        // Complete and put the data in the buffer
        // CryptHmacEnd(&hState, bytes, stream);;
        rc = CryptHmacEnd_Helper(&ctx, hashAlg, keySize, key, bytes, stream);
        if(rc != 0){
            printf("%s\n", "Error CryptHmacEnd_Helper");
            return 1;
        }

        LOGBLOB_DEBUG(stream, bytes, "stream");

        stream = &stream[digestSize];

        // printf("Stream1 %ld,\n", bytes);
        // for (int i = 0; i < bytes; i++){
        //     printf("%02x:", stream[i]);
        // }
        // printf("\n");
    }
    // Masking in the KDF is disabled. If the calling function wants something
    // less than even number of bytes, then the caller should do the masking
    // because there is no universal way to do it here
    if(counterInOut != NULL){
        *counterInOut = counter;
    }

    // mbedtls_md_free(&ctx);
    mbedtls_sha256_free(&ctx);

    return generated;
}

// CryptHmacStart
int CryptHmacStart_Helper(
    // mbedtls_md_context_t    *ctx,
    mbedtls_sha256_context  *ctx,
    uint16_t                 hashAlg,       // IN: the algorithm to use
    size_t                  *keySize,       // IN: the size of the HMAC key
    uint8_t                 *key            // IN: the HMAC key
)
{
    if (hashAlg != ALG_SHA256){
        printf("%s\n", "Hash Algorithm not supported yet");
        return 0;
    }

    uint8_t *pb;
    uint32_t i;

    // XOR the key with iPad (0x36)
    pb = key;
    for (i = *keySize; i > 0; i--){
        *pb++ ^= 0x36;
    }

    // if the keySize is smaller than a block, fill the rest with 0x36
    for(i = SHA256_BLOCK_SIZE - *keySize; i > 0; i--){
        *pb++ = 0x36;
    }

    // Increase the oPadSize to a full block
    // state->hmacKey.t.size = hashDef->blockSize;
    *keySize=SHA256_BLOCK_SIZE;


    // Start a new hash with the HMAC key
    // This will go in the caller's state structure and may be a sequence or not
    // CryptHashStart((PHASH_STATE)state, hashAlg);
    LOGBLOB_DEBUG(key, *keySize, "New key 1");

    rc = mbedtls_sha256_starts_ret(ctx, 0); /* 0 for SHA-256, or 1 for SHA-224 */
    // rc = mbedtls_md_hmac_starts(ctx, key, *keySize);
    if(rc != 0){
        printf("%s\n", "Error mbedtls_md_hmac_starts");
        return 0;
    }

    // CryptDigestUpdate((PHASH_STATE)state, state->hmacKey.t.size,
    //               state->hmacKey.t.buffer);
    rc = mbedtls_sha256_update_ret(ctx, key, *keySize);
    // rc = mbedtls_md_hmac_update(ctx, key, *keySize);
    if (rc != 0) {
        printf("%s\n", "Error mbedtls_md_hmac_update key");
        return 1;
    }

    // XOR the key block with 0x5c ^ 0x36
    // for(pb = state->hmacKey.t.buffer, i = hashDef->blockSize; i > 0; i--)
    // *pb++ ^= (0x5c ^ 0x36);
    for(pb = key, i = SHA256_BLOCK_SIZE; i > 0; i--){
        *pb++ ^= (0x5c ^ 0x36);
    }

    // printf("New key 2 (%d): ", *keySize);
    // for (int i = 0; i < *keySize; i++){
    //     printf("%02x", key[i]);
    // }
    // printf("\n");

    return SHA256_DIGEST_SIZE;   
}

/* 10.2.13.7.2  CryptHmacEnd() */
/* This function is called to complete an HMAC. It will finish the current digest, and start a new digest. It will then add the oPadKey and the completed digest and return the results in dOut. It will not return more than dOutSize bytes. */
/*     Return Value Meaning */
/*     >= 0 number of bytes in dOut (may be zero) */
// CryptHmacEnd
int CryptHmacEnd_Helper(
        // mbedtls_md_context_t   *ctx,
        mbedtls_sha256_context *ctx,
        TPM2_ALG_ID             hashAlg,       // IN: hash algorithm used in HMAC
        uint16_t                keySize,       // IN: the size of the HMAC key
        uint8_t                *key,            // IN: the HMAC key
        size_t                  dOutSize,      // IN: size of digest buffer // 32
        uint8_t                *dOut           // OUT: hash digest
){
    uint8_t temp[SHA256_DIGEST_SIZE];
    memset(temp, 0x00, SHA256_DIGEST_SIZE);
    // PHASH_STATE          hState = (PHASH_STATE)&state->hashState;
    
// #if SMAC_IMPLEMENTED
//     if(hState->type == HASH_STATE_SMAC)
//     return (state->hashState.state.smac.smacMethods.end)
//         (&state->hashState.state.smac.state,
//          dOutSize,
//          dOut);
// #endif
    // pAssert(hState->type == HASH_STATE_HMAC);
    // hState->def = CryptGetHashDef(hState->hashAlg);
    // Change the state type for completion processing
    // hState->type = HASH_STATE_HASH;

    if(hashAlg == ALG_NULL)
        dOutSize = 0;
    else{
        // Complete the current hash
        // HashEnd(hState, hState->def->digestSize, temp);
        rc = mbedtls_sha256_finish_ret(ctx, temp);
        // rc = mbedtls_md_hmac_finish(ctx, temp);
        if(rc != 0){
            printf("%s\n", "Error mbedtls_md_hmac_finish");
            return 1;
        }

        // printf("Temp (%d): ", TPM2_SHA256_DIGEST_SIZE);
        // for (size_t i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++)
        // {
        //     printf("%02x", temp[i]);
        // }
        // printf("\n");

        // printf("key (%d): ", keySize);
        // for (size_t i = 0; i < keySize; i++)
        // {
        //     printf("%02x", key[i]);
        // }
        // printf("\n");
        

        // Do another hash starting with the oPad
        // CryptHashStart(hState, hState->hashAlg);
        rc = mbedtls_sha256_starts_ret(ctx, 0); /* 0 for SHA-256, or 1 for SHA-224 */
        // rc = mbedtls_md_hmac_starts(ctx, key, keySize);
        if(rc != 0){
            printf("%s\n", "Error mbedtls_md_hmac_starts");
            return 0;
        }
        // CryptDigestUpdate(hState, state->hmacKey.t.size, state->hmacKey.t.buffer);
        rc = mbedtls_sha256_update_ret(ctx, key, keySize); /* keySize = 64 */
        // rc = mbedtls_md_hmac_update(ctx, key, keySize);
        if (rc != 0) {
            printf("%s\n", "Error mbedtls_md_hmac_update counter");
            return 1;
        }
        // CryptDigestUpdate(hState, hState->def->digestSize, temp);
        rc = mbedtls_sha256_update_ret(ctx, temp, SHA256_DIGEST_SIZE /* 32 */);
        // rc = mbedtls_md_hmac_update(ctx, temp, TPM2_SHA_DIGEST_SIZE);
        if (rc != 0) {
            printf("%s\n", "Error mbedtls_md_hmac_update counter");
            return 1;
        }
    }

    rc = mbedtls_sha256_finish_ret(ctx, dOut);
    // rc = mbedtls_md_hmac_finish(ctx, dOut);
    if(rc != 0){
        printf("%s\n", "Error mbedtls_md_hmac_finish");
        return 1;
    }

    return 0;
}

int createHMACPolicySigned(uint16_t hashAlg, uint8_t *key, size_t keySize, 
    uint8_t *nonceTPM, size_t nonceTPMSize, uint32_t expiration, 
    uint8_t *cpHashA, size_t cpHashASize, uint8_t *policyRef, size_t policyRefSize,
    uint8_t *outputMac, size_t *outputMacSize){

    if (hashAlg != ALG_SHA256){
        printf("ERROR: Specified Algorithm not yet implemented.\n");
        return 1;
    }

    
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    rc = mbedtls_sha256_starts_ret (&sha_ctx, 0 /* = use SHA256 */);
    if (rc != 0){
        printf("Error: mbedtls_sha256_starts\n");
        return 1;
    }

    char *digest;
    int digestSize = SHA256_DIGEST_SIZE;
    digest = malloc(digestSize*sizeof(UINT32));

    mbedtls_sha256_update_ret (&sha_ctx, nonceTPM, nonceTPMSize);
    // mbedtls_sha256_update_ret (&sha_ctx, &((BYTE *)&expiration)[8 - sizeof(UINT32)], sizeof(UINT32));
    mbedtls_sha256_update_ret (&sha_ctx, (char*) &expiration, sizeof(UINT32));
    mbedtls_sha256_update_ret (&sha_ctx, cpHashA, cpHashASize);
    mbedtls_sha256_update_ret (&sha_ctx, policyRef, policyRefSize);
    mbedtls_sha256_finish_ret (&sha_ctx, digest);
    mbedtls_sha256_free(&sha_ctx);

    LOGBLOB_DEBUG(digest, digestSize, "digest");

    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);

    rc = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1 /* non-zero: HMAC is used with this context */);
    if (rc != 0){
        printf("Error: mbedtls_md_setup\n");
        return 1;
    }

    rc = mbedtls_md_hmac_starts(&ctx,key,keySize);
    if (rc != 0){
        printf("Error: mbedtls_md_hmac_starts\n");
        return 1;
    }

    rc = mbedtls_md_hmac_update(&ctx, digest, digestSize);
    if (rc != 0){
        printf("Error: mbedtls_md_hmac_update\n");
        return 1;
    }

    rc = mbedtls_md_hmac_finish(&ctx, outputMac);
    if (rc != 0){
        printf("Error: mbedtls_md_hmac_update\n");
        return 1;
    }
    *outputMacSize = SHA256_DIGEST_SIZE;

    LOGBLOB_DEBUG(outputMac, *outputMacSize, "outputMac");

    mbedtls_md_free(&ctx);

    return 0;

}

int createHMAC(uint16_t hashAlg, uint8_t *key, size_t keySize, uint8_t *data, 
    size_t dataSize, uint8_t *outputMac, size_t *outputMacSize){

    if (hashAlg != ALG_SHA256){
        printf("ERROR: Specified Algorithm not yet implemented.\n");
        return 1;
    }
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);

    rc = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1 /* non-zero: HMAC is used with this context */);
    if (rc != 0){
        printf("Error: mbedtls_md_setup\n");
        return 1;
    }

    rc = mbedtls_md_hmac_starts(&ctx,key,keySize);
    if (rc != 0){
        printf("Error: mbedtls_md_hmac_starts\n");
        return 1;
    }

    rc = mbedtls_md_hmac_update(&ctx, data, dataSize);
    if (rc != 0){
        printf("Error: mbedtls_md_hmac_update\n");
        return 1;
    }

    rc = mbedtls_md_hmac_finish(&ctx, outputMac);
    if (rc != 0){
        printf("Error: mbedtls_md_hmac_update\n");
        return 1;
    }
    *outputMacSize = SHA256_DIGEST_SIZE;

    mbedtls_md_free(&ctx);

    return 0;
}


int createHMACOpenSSL(uint16_t hashAlg, uint8_t *key, size_t keySize, uint8_t *data, 
    size_t dataSize, uint8_t *outputMac, size_t *outputMacSize){

    if (hashAlg != ALG_SHA256){
        printf("ERROR: Specified Algorithm not yet implemented.\n");
        return 1;
    }

    HMAC_CTX *ctx = HMAC_CTX_new();
    // EVP_MD *evp_md = EVP_sha256();

    rc = HMAC_Init_ex(ctx, key, keySize, EVP_sha256(), 0);
    if (rc != 1){
        printf("Error: HMAC_Init_ex\n");
        return 1;
    }

    rc = HMAC_Update(ctx, data, dataSize);
    if (rc != 1){
        printf("Error: HMAC_Update\n");
        return 1;
    }

    // digestOpenSSL = (TPM2B_DIGEST*) malloc(sizeof(TPM2B_DIGEST));

    unsigned int len = 0;

    rc = HMAC_Final(ctx, outputMac, &len);
    if (rc != 1){
        printf("Error: Esys_CreateLoaded\n");
        return 1;
    }

    *outputMacSize = len;

    // digestOpenSSL->size = len;

    // printf("HMAC of OSSL: ");  
    // for (int i = 0; i < digestOpenSSL->size; i++){
    //     printf("%02x", digestOpenSSL->buffer[i]);
    // }
    // printf("\n");

    // memcpy(outputMac, digestOpenSSL->buffer, digestOpenSSL->size);
    // *outputMacSize = digestOpenSSL->size;

    // free(digestOpenSSL);
    HMAC_CTX_free(ctx);

    return 0;
}
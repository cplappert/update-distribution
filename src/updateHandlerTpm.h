/*******************************************************************
 *
 * 1. Create Derivation parent (sensitive value is used as key in KDF)
 * 2. Create Object under Derivation parent 
 *      * For object derivation the TPM uses the sensitive value in a Derivation
 *        Parent as a key in a key derivation function (KDF)
 *      * TPM2_CreateLoaded -> 
            * The TPM allows two additional parameters (label and context) to be
            provided in TPM2_CreateLoaded(). These additional parameters can be
            provided in two ways: in the unique field of the inPublic value, or
            in the data field of the inSensitive parameter. If provided in the
            unique field, the corresponding value in the inSensitive.data field
            is ignored.

 * Inner KDF: K(i) ≔ HMAC (KI , [i] 2 || Label || 00 16 || Context || [L] 2 )
 *      KI := Sensitive Value of Derivation Parent
 *      Label := 
 ******************************************************************/

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/hmac.h>

/* From TCG Algorithm Registry: Definition of TPM2_ALG_ID Constants */
typedef uint16_t ALG_ID;
#define ALG_SHA256 ((ALG_ID) 0x000B)
#define KDF_LIMIT 8192 

int init(ESYS_CONTEXT **ctx, TSS2_TCTI_CONTEXT *tcti_ctx, char *tcti_name);
int verify_loaded_key(ESYS_CONTEXT **ctx, uint8_t *tobesigned, 
    size_t tobesignedSize, TPMT_SIGNATURE signature, ESYS_TR loadedKeyHandle);
int load_external_key_from_pem(ESYS_CONTEXT **ctx, char *file_path, uint16_t TPM2_ALG_ID,
    ESYS_TR *loaded_key_handle);
int create_authorization_policy(ESYS_CONTEXT **ctx, TPM2B_NONCE nonce_caller,
    TPM2_SE session_type, ESYS_TR **session, ESYS_TR loaded_key_handle,
    TPM2B_DIGEST **policy_digest);
// int executeRKP(ESYS_CONTEXT **ctx, TPM2B_NONCE nonceCaller, ESYS_TR **session,
//     TPM2B_DIGEST *templateHash, TPM2B_DIGEST *sessionHash, ESYS_TR nvSessionHashHandle, 
//     TPM2_SE session_type, TPM2B_DIGEST **policyDigest);
int executeRKP(ESYS_CONTEXT **ctx, TPM2B_NONCE nonceCaller, ESYS_TR **session,
    TPM2B_DIGEST *templateHash, TPM2B_DIGEST *sessionHash, ESYS_TR nvSessionHashHandle, 
    TPM2_SE session_type, TPM2B_DIGEST **policyDigest
#ifdef PERFORMANCE 
    , char *perfLog
#endif
    );
    // , char *perfLog);
int executeIAP(ESYS_CONTEXT **ctx, TPM2B_NONCE nonceCaller, ESYS_TR **session,
    TPM2B_DIGEST *templateHash, ESYS_TR nvRevocationHandle, ESYS_TR authObject,
    TPM2_SE session_type, TPM2B_DIGEST inputMac, TPM2B_NONCE nonceTPM, 
    TPM2B_DIGEST **policyDigest
#ifdef PERFORMANCE 
    , char *perfLog
#endif
    );
int verifySignature(ESYS_CONTEXT **ctx, ESYS_TR loaded_key_handle, 
    uint8_t *der_signature, size_t der_signature_size, TPM2B_DIGEST digest, uint16_t alg
#ifdef PERFORMANCE 
    , char *perfLog
#endif
    );
int authorizePolicy(ESYS_CONTEXT **ctx, ESYS_TR **session, ESYS_TR loaded_key_handle, 
    uint8_t *der_signature, size_t der_signature_size, uint8_t *policy_digest, 
    size_t policy_digest_size, uint8_t *policyRef, size_t policyRefSize, uint16_t TPM2_ALG_ID);
int get_template_session_digest(ESYS_CONTEXT **ctx, TPM2B_NONCE nonceCaller,
    TPM2B_DIGEST *policyDigest, TPM2_SE session_type, ESYS_TR **session_handle,
    TPM2B_DIGEST *templateHash);
int createSymAuthKey(ESYS_CONTEXT **ctx, ESYS_TR *keyHandle, uint32_t persistent_index, 
    TPM2B_DIGEST policyDigest);
int createDerivationParent(ESYS_CONTEXT **ctx, ESYS_TR *keyHandleDerivationParent, 
    uint32_t persistent_index, uint8_t *rawKey, uint16_t rawKeySize, 
    TPM2B_DIGEST policyDigest);
int deriveUpdateKey(ESYS_CONTEXT **ctx, uint32_t persistent_index,
    uint8_t *label, uint16_t labelSize,
    uint8_t *context, uint16_t contextSize, ESYS_TR **derived_key_handle, 
    ESYS_TR session);
int createUpdateKeyOpenSSL(uint16_t hashAlg, TPM2B_DATA seed, 
    TPM2B_LABEL label, TPM2B_LABEL context, UINT32 limit, 
    UINT32 expectedKeySize, uint8_t *derivedKey);
void getCurrentPolicyDigest(ESYS_CONTEXT *ctx, ESYS_TR *session);
int createHMACTPM(ESYS_CONTEXT **ctx, uint16_t hashAlg, uint32_t key_handle,
    uint8_t *data, uint32_t dataSize, uint8_t *outputMac, size_t *outputMacSize);

void cleanup(ESYS_CONTEXT **ctx, ESYS_TR handle);
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

/*
    - Base Key Creation
    - 
*/

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include "mbedtls/sha256.h"

#include "updateHandlerTpm.h"
#include "fileHandler.h"
#include "tpm2_templates.h"
#include "osslUtils.h"

// #include "mbedtls/ecdsa.h"
// #include "mbedtls/bignum.h"
// #include "mbedtls/asn1.h"

#include <unistd.h>

#define LOGMODULE update
#include "util/log.h"

#ifdef PERFORMANCE
#include <time.h>
#include <sys/time.h>
struct timespec start_overall, end_overall, start_policy_exec_1, end_policy_exec_1, start_policy_exec_2, end_policy_exec_2, start_policy_exec_3, end_policy_exec_3;
// clock_t start_overall_cpu, end_overall_cpu, start_policy_exec_1_cpu, end_policy_exec_1_cpu, start_policy_exec_2_cpu, end_policy_exec_2_cpu, start_policy_exec_3_cpu, end_policy_exec_3_cpu;
#endif


#define PERSISTENT_BASE_KEY         0x81000001
#define PERSISTENT_BASE_KEY_PW      0x81000002
#define BUFFERSIZE                  13 //64 //32
#define NANOSECOND_DIVISOR          1000000
#define SECOND_MULTIPLIER           1000

/*  Initialize variables for derivation parent key and update key
 *  handles.
 */

/* Initialize variable for context.*/
ESYS_CONTEXT *ctx = NULL;

/* Initialize variable for return values.*/
uint32_t r = 0;

/* Initialize data structure for primary key's authentication
 * value.
 */
TPM2B_AUTH authValuePrimary = {
    .size = 5,
    .buffer = {1, 2, 3, 4, 5}
};

/* Define variables for the command's responses.*/
TPM2B_PUBLIC *outPublic;
TPM2B_CREATION_DATA *creationData;
TPM2B_DIGEST *creationHash;
TPMT_TK_CREATION *creationTicket;


int init(ESYS_CONTEXT **ctx, TSS2_TCTI_CONTEXT *tcti_ctx, char *tcti_name) {

    /* Initialize the ESAPI context.*/
    r = Esys_Initialize(ctx, tcti_ctx, NULL);
    if (r != TSS2_RC_SUCCESS) {
        printf("Error: Esys_Initialize\n");
        return 1;
    }

    // memcpy(tcti_ctx_io, tcti_ctx, sizeof(TSS2_TCTI_CONTEXT_COMMON_V2));

    if(strstr(tcti_name, "swtpm") || strstr(tcti_name, "sim")){
        LOG_DEBUG("Start the Simulator");
        /* Startup TPM */
        r = Esys_Startup(*ctx, TPM2_SU_CLEAR);
        if (r != TSS2_RC_SUCCESS && r != TPM2_RC_INITIALIZE) {
            printf("Error: Esys_Startup\n");
            return 1;
        }
    }
    else{
        LOG_DEBUG("Not Started the Simulator");
    }

    return 0;
}

int load_external_key_from_pem(ESYS_CONTEXT **ctx, char *file_path, uint16_t TPM2_ALG_ID,
    ESYS_TR *loaded_key_handle){

    TPM2B_PUBLIC inPublic;
    memcpy(&inPublic, &keyEcTemplate, sizeof(TPM2B_PUBLIC));

    r = tpm2_openssl_load_public(file_path, TPM2_ALG_ID, &inPublic);
    if (r!=0) {
        LOG_ERROR("tpm2_openssl_load_public");
        return 1;
    }

    // ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
    r = Esys_LoadExternal(*ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL,
        &inPublic, ESYS_TR_RH_OWNER, loaded_key_handle);
    if (r != TSS2_RC_SUCCESS){
        printf("Error: Esys_LoadExternal\n");
        return 1;
    }   
}


int create_authorization_policy(ESYS_CONTEXT **ctx, TPM2B_NONCE nonce_caller,
    TPM2_SE session_type, ESYS_TR **session, ESYS_TR loaded_key_handle,
    TPM2B_DIGEST **policy_digest){


    /* Get the name of the signature key. The key name will be
     * embedded into the policy.
     */

    TPM2B_NAME *nameKeySign;
    nameKeySign = malloc(sizeof(TPM2B_NAME));

    r = Esys_TR_GetName(*ctx, loaded_key_handle, &nameKeySign);
    if (r != TSS2_RC_SUCCESS){
        // cleanup(ctx, loadedKeyHandle);
        LOG_ERROR("Esys_TR_GetName");
        return 1;
    }

    TPMT_SYM_DEF symmetricTrial = {.algorithm = TPM2_ALG_NULL};

    r = Esys_StartAuthSession(*ctx,
        ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &nonce_caller,
        session_type,
        &symmetricTrial, TPM2_ALG_SHA256,
        *session);
    if (r != 0) {
        LOG_ERROR("Error: Esys_StartAuthSession\n");
        return 1;
    }

    /* Execute ESAPI command to include the signature key name
     * in the created policy.
     */
    TPM2B_DIGEST approvedPolicy = {0};
    TPM2B_NONCE policyRef = {
        .size = 0,
        .buffer={0x01,0x02,0x03,0x04,0x05}
    };
    TPMT_TK_VERIFIED  checkTicket = {
        .tag = TPM2_ST_VERIFIED,
        .hierarchy = TPM2_RH_OWNER,
        .digest = {0}
    };

    r = Esys_PolicyAuthorize(*ctx, **session, ESYS_TR_NONE, ESYS_TR_NONE, 
        ESYS_TR_NONE, &approvedPolicy, &policyRef, nameKeySign, &checkTicket);    
    if (r != 0) {
        LOG_ERROR("Error: Esys_PolicyAuthorize");
        return 1;
    }

    // LOGBLOB_ERROR(policy_digest->buffer, policy_digest->size, "policyDigestIB");
    r = Esys_PolicyGetDigest(*ctx, **session, ESYS_TR_NONE, ESYS_TR_NONE, 
        ESYS_TR_NONE, policy_digest);
    if(r != 0){
        LOG_ERROR("Esys_PolicyGetDigest FAILED! Response Code : 0x%x\n", r);
        return r;
    }
    // LOGBLOB_ERROR(((TPM2B_DIGEST*)&policy_digest)->buffer, ((TPM2B_DIGEST*)&policy_digest)->size, "policyDigestIA");

    return 0;
}

int executeRKP(ESYS_CONTEXT **ctx, TPM2B_NONCE nonceCaller, ESYS_TR **session,
    TPM2B_DIGEST *templateHash, TPM2B_DIGEST *sessionHash, ESYS_TR nvSessionHashHandle, 
    TPM2_SE session_type, TPM2B_DIGEST **policyDigest
#ifdef PERFORMANCE 
    , char *perfLog
#endif
){

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_overall);
    // start_overall_cpu = clock();
    #endif

    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};

    r = Esys_StartAuthSession(*ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, 
                              ESYS_TR_NONE, &nonceCaller,
                              session_type, &symmetric, 
                              TPM2_ALG_SHA256, *session);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_StartAuthSession");
        return 1;
    }

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_policy_exec_1);
    // start_policy_exec_1_cpu = clock();
    #endif

    r = Esys_PolicyTemplate(*ctx, **session,
    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, templateHash);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_PolicyTemplate");
        return 1;
    }

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_policy_exec_1);
    // end_policy_exec_1_cpu = clock();
    #endif

    TPM2B_OPERAND operandB;
    operandB.size=sessionHash->size;

    memcpy(&operandB.buffer, sessionHash->buffer, operandB.size);

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_policy_exec_2);
    // start_policy_exec_2_cpu = clock();
    #endif

    r = Esys_PolicyNV(*ctx, ESYS_TR_RH_OWNER, nvSessionHashHandle, **session,
    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &operandB, 0 /* Offset*/, TPM2_EO_EQ  /* with TPM2_EO_NEQ: EC 0x126 tpm:error(2.0): policy failure in math operation or an invalid authPolicy value */ ); 
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_PolicyNV");
        return 1;
    }

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_policy_exec_2);
    // end_policy_exec_2_cpu = clock();
    #endif

    r = Esys_PolicyGetDigest(*ctx, **session, ESYS_TR_NONE, ESYS_TR_NONE, 
        ESYS_TR_NONE, policyDigest);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_PolicyNV");
        return 1;
    }

    LOGBLOB_DEBUG(((TPM2B_DIGEST*) *policyDigest)->buffer, 
        ((TPM2B_DIGEST*) *policyDigest)->size, 
        "Esys_PolicyTemplate|Esys_PolicyNV In");

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_overall);
    // end_overall_cpu = clock();
    #endif

    if(session_type == TPM2_SE_POLICY){
        char buffer[2048] = {"\0"};
        memset(buffer, '\0', 1);
        size_t bufferSize = BUFFERSIZE;

        snprintf(buffer + strlen(buffer), bufferSize, "%f,",
            ((end_overall.tv_sec - start_overall.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_overall.tv_nsec - start_overall.tv_nsec) /  (double) NANOSECOND_DIVISOR));
        snprintf(buffer + strlen(buffer), bufferSize, "%f,",
            ((end_policy_exec_1.tv_sec - start_policy_exec_1.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_policy_exec_1.tv_nsec - start_policy_exec_1.tv_nsec) / (double)NANOSECOND_DIVISOR));
        snprintf(buffer + strlen(buffer), bufferSize, "%f,",
            ((end_policy_exec_2.tv_sec - start_policy_exec_2.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_policy_exec_2.tv_nsec - start_policy_exec_2.tv_nsec) / (double)NANOSECOND_DIVISOR));

        strncpy(perfLog + strlen(perfLog), buffer, strlen(buffer)+1);
    }

    return 0;

}

int executeIAP(ESYS_CONTEXT **ctx, TPM2B_NONCE nonceCaller, ESYS_TR **session,
    TPM2B_DIGEST *templateHash, ESYS_TR nvRevocationHandle, ESYS_TR authObject,
    TPM2_SE session_type, TPM2B_DIGEST inputMac, TPM2B_NONCE nonceTPM, 
    TPM2B_DIGEST **policyDigest
#ifdef PERFORMANCE 
    , char *perfLog
#endif
    ){

    // LOG_ERROR("PERFLOG: %s", perfLog);

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_overall);
    // start_overall_cpu = clock();
    #endif

    // #ifdef PERFORMANCE
    // clock_gettime(CLOCK_MONOTONIC_RAW, &start_policy_exec_1);
    // // start_policy_exec_1_cpu = clock();
    // #endif

    r = Esys_PolicyTemplate(*ctx, **session,
    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, templateHash);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_PolicyTemplate");
        return 1;
    }

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_policy_exec_1);
    // end_policy_exec_1_cpu = clock();
    #endif

    TPM2B_OPERAND operandB = {
        .size=1,
        .buffer={0}
    };

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_policy_exec_2);
    // start_policy_exec_2_cpu = clock();
    #endif

    r = Esys_PolicyNV(*ctx, ESYS_TR_RH_OWNER, nvRevocationHandle, **session,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &operandB, 0 /* Offset*/, 
        TPM2_EO_EQ);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_PolicyNV");
        return 1;
    }

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_policy_exec_2);
    // end_policy_exec_2_cpu = clock();
    #endif   

    TPMT_SIGNATURE signatureStruct;
    signatureStruct.sigAlg = TPM2_ALG_HMAC;
    signatureStruct.signature.hmac.hashAlg = TPM2_ALG_SHA256;
    memcpy(signatureStruct.signature.hmac.digest.sha256, inputMac.buffer, 
        TPM2_SHA256_DIGEST_SIZE);

    TPM2B_NONCE policyRef = {0};
    TPM2B_DIGEST cpHashA = {0};

    LOGBLOB_DEBUG(signatureStruct.signature.hmac.digest.sha256, TPM2_SHA256_DIGEST_SIZE, "inputMac");
    LOGBLOB_DEBUG(nonceTPM.buffer, nonceTPM.size, "nonceTPM");

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_policy_exec_3);
    // start_policy_exec_3_cpu = clock();
    #endif   

    r = Esys_PolicySigned(*ctx, authObject, **session, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &nonceTPM, &policyRef, &cpHashA, 0, 
        &signatureStruct, NULL, NULL);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_PolicySigned");
        return 1;
    }

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_policy_exec_3);
    // end_policy_exec_3_cpu = clock();
    #endif  

    r = Esys_PolicyGetDigest(*ctx, **session, ESYS_TR_NONE, ESYS_TR_NONE, 
        ESYS_TR_NONE, policyDigest);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_PolicyNV");
        return 1;
    }

    if(session_type == TPM2_SE_POLICY){
        char buffer[2048];
        memset(buffer, '\0', 1);
        size_t bufferSize = BUFFERSIZE;

        snprintf(buffer + strlen(buffer), bufferSize, "%f,",
            ((end_policy_exec_3.tv_sec - start_overall.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_policy_exec_3.tv_nsec - start_overall.tv_nsec) / (double) NANOSECOND_DIVISOR));

        snprintf(buffer + strlen(buffer), bufferSize, "%f,",
            ((end_policy_exec_1.tv_sec - start_overall.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_policy_exec_1.tv_nsec - start_overall.tv_nsec) / (double) NANOSECOND_DIVISOR));

        snprintf(buffer + strlen(buffer), bufferSize, "%f,",
            ((end_policy_exec_2.tv_sec - start_policy_exec_2.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_policy_exec_2.tv_nsec - start_policy_exec_2.tv_nsec) / (double) NANOSECOND_DIVISOR));

        snprintf(buffer + strlen(buffer), bufferSize, "%f,",
            ((end_policy_exec_3.tv_sec - start_policy_exec_3.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_policy_exec_3.tv_nsec - start_policy_exec_3.tv_nsec) / (double) NANOSECOND_DIVISOR));

        strncpy(perfLog + strlen(perfLog), buffer, strlen(buffer)+1);
    }


    return 0;
}

static int
ifapi_bn2binpad(const BIGNUM *bn, unsigned char *bin, int binSize)
{
    /* Check for NULL parameters */
    return_if_null(bn, "bn is NULL", 0);
    return_if_null(bin, "bin is NULL", 0);

    /* Convert bn */
    int bnSize = BN_num_bytes(bn);
    int offset = binSize - bnSize;
    memset(bin, 0, offset);
    BN_bn2bin(bn, bin + offset);
    return 1;
}

int verifySignature(ESYS_CONTEXT **ctx, ESYS_TR loaded_key_handle, 
    uint8_t *der_signature, size_t der_signature_size, TPM2B_DIGEST digest, uint16_t alg
#ifdef PERFORMANCE 
    , char *perfLog
#endif
    ){

    LOGBLOB_DEBUG(der_signature, der_signature_size, "readSig: ");

    TPMT_SIGNATURE *signature = malloc(sizeof(TPMT_SIGNATURE));

    switch (alg) {
    case TPM2_ALG_RSA:      
        signature->sigAlg = TPM2_ALG_RSASSA;
        signature->signature.rsassa.hash = TPM2_ALG_SHA256;
        signature->signature.rsassa.sig.size = der_signature_size;
        memcpy(signature->signature.rsassa.sig.buffer, der_signature, der_signature_size);

        LOGBLOB_DEBUG(signature->signature.rsassa.sig.buffer, 
            signature->signature.rsassa.sig.size, "SigRSA: ");
        break;
    case TPM2_ALG_ECC:
        signature->sigAlg = TPM2_ALG_ECDSA;
        signature->signature.ecdsa.hash = TPM2_ALG_SHA256;

        ECDSA_SIG *ecdsaSignature = NULL;
        const BIGNUM *bnr;
        const BIGNUM *bns;

        if (d2i_ECDSA_SIG(&ecdsaSignature, (const unsigned char**) &der_signature, der_signature_size) == NULL){
            LOG_ERROR("d2i_ECDSA_SIG returned NULL. Is the signature correct?");
            return 1;
        }

        ECDSA_SIG_get0(ecdsaSignature, &bnr, &bns);

        int keySize = 32;
        ifapi_bn2binpad(bnr, &signature->signature.ecdsa.signatureR.buffer[0],
                       keySize);
        signature->signature.ecdsa.signatureR.size = keySize;
        ifapi_bn2binpad(bns, &signature->signature.ecdsa.signatureS.buffer[0],
                       keySize);
        signature->signature.ecdsa.signatureS.size = keySize;



        /* mbedtls_ecdsa_read_signature_restartable */

        // unsigned char *p = (unsigned char *) der_signature;
        // const unsigned char *end = (unsigned char *) der_signature + der_signature_size;
        // size_t len;
        // mbedtls_mpi R, S;
        // mbedtls_mpi_init( &R );
        // mbedtls_mpi_init( &S );

        // if( ( r = mbedtls_asn1_get_tag( &p, end, &len,
        //             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 ){
        //     LOG_ERROR("MBEDTLS_ERR_ECP_BAD_INPUT_DATA");
        //     return 1;
        // }

        // if( p + len != end ) {
        //     // ret = MBEDTLS_ERROR_ADD( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
        //     //       MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        //     LOG_ERROR("MBEDTLS_ERR_ECP_BAD_INPUT_DATA + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH");
        //     return 1;
        // }

        // if( ( r = mbedtls_asn1_get_mpi( &p, end, &R ) ) != 0 ||
        // ( r = mbedtls_asn1_get_mpi( &p, end, &S ) ) != 0 ){
        //     LOG_ERROR("MBEDTLS_ERR_ECP_BAD_INPUT_DATA");
        //     return 1;
        // }

        // for(int i = R.n; i > 0; i++){
        //     TODO: Convert R.p[i] to byteArray
        // }

        LOGBLOB_DEBUG(signature->signature.ecdsa.signatureR.buffer, 
            signature->signature.ecdsa.signatureR.size, "SigR: ");
        LOGBLOB_DEBUG(signature->signature.ecdsa.signatureS.buffer, 
            signature->signature.ecdsa.signatureS.size, "SigS: ");

        break;
    default:
        /* default try TSS */
        LOG_ERROR("Default not implemented yet");
        return 1;
    }

    // LOGBLOB_DEBUG(ahash2b.buffer, ahash2b.size, "ToBeSigned ");

    #ifdef PERFORMANCE
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_overall);
    // start_overall_cpu = clock();
    #endif

    LOG_DEBUG("loaded_key_handle 2: %02x", loaded_key_handle);

    r = Esys_VerifySignature(*ctx, loaded_key_handle, ESYS_TR_NONE, ESYS_TR_NONE,
      ESYS_TR_NONE, &digest, signature, NULL);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_VerifySignature");
        free(signature);
        return 1;
    }

    #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_overall);
        char buffer[2048] = {"\0"};
        // LOG_ERROR("In1.5:(%f)\n", strlen(perfLog));
        size_t bufferSize = BUFFERSIZE; // (sizeof(uint64_t)+10);
        snprintf(buffer + strlen(buffer), bufferSize, "%f,",
            ((end_overall.tv_sec - start_overall.tv_sec) * SECOND_MULTIPLIER + 
            (double)(end_overall.tv_nsec - start_overall.tv_nsec) / (double)NANOSECOND_DIVISOR));
        // snprintf(buffer + strlen(buffer), bufferSize, "%f,",(start_overall.tv_nsec / 1000000 + start_overall.tv_sec * 1000));
        // snprintf(buffer + strlen(buffer), bufferSize, "%f,", (end_overall.tv_nsec / 1000000 + end_overall.tv_sec * 1000));
        strncpy(perfLog + strlen(perfLog), buffer, strlen(buffer)+1);
    #endif

    return 0;
}



int authorizePolicy(ESYS_CONTEXT **ctx, ESYS_TR **session, ESYS_TR loaded_key_handle, 
    uint8_t *der_signature, size_t der_signature_size, uint8_t *policy_digest, 
    size_t policy_digest_size, uint8_t *policyRef, size_t policyRefSize, uint16_t alg){

    LOGBLOB_DEBUG(der_signature, der_signature_size, "readSig: ");

    TPMT_TK_VERIFIED *validationTicket2;
    TPM2B_DIGEST ahash2b;
    unsigned char hash[TPM2_SHA256_DIGEST_SIZE];

    TPM2B_NONCE policyRef2b;
    policyRef2b.size = policyRefSize;
    memcpy(policyRef2b.buffer, policyRef, policyRefSize);

    uint8_t *tobesigned;
    size_t tobesignedSize = policy_digest_size + policyRefSize;
    tobesigned = malloc(tobesignedSize);
    memcpy(tobesigned, policy_digest, policy_digest_size);
    memcpy(tobesigned+policy_digest_size, policyRef, policyRefSize);

    ahash2b.size = TPM2_SHA256_DIGEST_SIZE;

    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    r = mbedtls_sha256_starts_ret (&sha_ctx, 0 /* = use SHA256 */);
    if (r != 0){
        printf("Error: mbedtls_sha256_starts\n");
        free(tobesigned);
        return 1;
    }
    mbedtls_sha256_update_ret(&sha_ctx, tobesigned, tobesignedSize);
    mbedtls_sha256_finish_ret(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);

    memcpy(ahash2b.buffer, hash, ahash2b.size);

    free(tobesigned);

    TPMT_SIGNATURE *signature = malloc(sizeof(TPMT_SIGNATURE));

    switch (alg) {
    case TPM2_ALG_RSA:      

        signature->sigAlg = TPM2_ALG_RSASSA;
        signature->signature.rsassa.hash = TPM2_ALG_SHA256;
        signature->signature.rsassa.sig.size = der_signature_size;
        memcpy(signature->signature.rsassa.sig.buffer, der_signature, der_signature_size);

        // TPMT_SIGNATURE signatureStruct = {
        //     .sigAlg /* TPMI_ALG_SIG_SCHEME */ = TPM2_ALG_RSAPSS,
        //     .signature /* TPMU_SIGNATURE */ = {
        //         .rsassa /* TPMS_SIGNATURE_RSASSA . TPMS_SIGNATURE_RSA */ = {
        //             .hash /* TPMI_ALG_HASH  */ = TPM2_ALG_SHA256,
        //             .sig /* TPM2B_PUBLIC_KEY_RSA */ = {0}
        //         }
        //     },
        // };

        // signatureStruct.signature.rsassa.sig.size = der_signature_size;
        // memcpy(signatureStruct.signature.rsassa.sig.buffer, der_signature ,der_signature_size);
        LOGBLOB_DEBUG(signature->signature.rsassa.sig.buffer, 
            signature->signature.rsassa.sig.size, "SigRSA: ");


        break;
    case TPM2_ALG_ECC:
        // TPMT_SIGNATURE signatureStruct = {
        //     .sigAlg /* TPMI_ALG_SIG_SCHEME */ = TPM2_ALG_ECDSA,
        //     .signature /* TPMU_SIGNATURE */ = {
        //         .ecdsa /* TPMS_SIGNATURE_ECDSA . TPMS_SIGNATURE_ECC */ = {
        //             .hash /* TPMI_ALG_HASH */ =  TPM2_ALG_SHA256,
        //             .signatureR /* TPM2B_ECC_PARAMETER */ = {0},
        //             .signatureS /* TPM2B_ECC_PARAMETER */ = {0}
        //         },
        //     },
        // };

        signature->sigAlg = TPM2_ALG_ECDSA;
        signature->signature.ecdsa.hash = TPM2_ALG_SHA256;

        ECDSA_SIG *ecdsaSignature = NULL;
        const BIGNUM *bnr;
        const BIGNUM *bns;

        if (d2i_ECDSA_SIG(&ecdsaSignature, (const unsigned char**) &der_signature, der_signature_size) == NULL){
            LOG_ERROR("d2i_ECDSA_SIG returned NULL. Is the signature correct?");
            return 1;
        }

        ECDSA_SIG_get0(ecdsaSignature, &bnr, &bns);

        int keySize = 32;
        ifapi_bn2binpad(bnr, &signature->signature.ecdsa.signatureR.buffer[0],
                       keySize);
        signature->signature.ecdsa.signatureR.size = keySize;
        ifapi_bn2binpad(bns, &signature->signature.ecdsa.signatureS.buffer[0],
                       keySize);
        signature->signature.ecdsa.signatureS.size = keySize;


        // r = getRandSfromDerSignature(der_signature, der_signature_size, 
        //     signature->signature.ecdsa.signatureR.buffer, 
        //     &signature->signature.ecdsa.signatureR.size, 
        //     signature->signature.ecdsa.signatureS.buffer, 
        //     &signature->signature.ecdsa.signatureS.size);
        // if (r != TSS2_RC_SUCCESS){
        //     LOG_ERROR("getRandSfromDerSignature");
        //     free(signature);
        //     return 1;
        // }

        LOGBLOB_DEBUG(signature->signature.ecdsa.signatureR.buffer, 
            signature->signature.ecdsa.signatureR.size, "SigR: ");
        LOGBLOB_DEBUG(signature->signature.ecdsa.signatureS.buffer, 
            signature->signature.ecdsa.signatureS.size, "SigS: ");

        break;
    default:
        /* default try TSS */
        LOG_ERROR("Default not implemented yet");
        return 1;
    }

    LOGBLOB_DEBUG(ahash2b.buffer, ahash2b.size, "ToBeSigned ");

    r = Esys_VerifySignature(*ctx, loaded_key_handle, ESYS_TR_NONE, ESYS_TR_NONE,
      ESYS_TR_NONE, &ahash2b, signature, &validationTicket2);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_VerifySignature");
        free(signature);
        return 1;
    }
    else{
        LOG_DEBUG("SUCCESS: Esys_VerifySignature");
        LOGBLOB_DEBUG(validationTicket2->digest.buffer, validationTicket2->digest.size, "validationTicket2");
    }

    free(signature);

    TPM2B_NAME *nameKeySign;
    r = Esys_ReadPublic(*ctx,
        loaded_key_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        NULL, /* &outPublic, */
        &nameKeySign,
        NULL/* &keyQualifiedName */);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("ReadPublic");
        return 1;
    }

    TPM2B_DIGEST policyDigest;
    policyDigest.size = policy_digest_size;
    memcpy(policyDigest.buffer, policy_digest, policyDigest.size);

    LOGBLOB_DEBUG(nameKeySign->name, nameKeySign->size, "KeyName");
    LOGBLOB_DEBUG(policyDigest.buffer, policyDigest.size, "Policy Digest");
    LOGBLOB_DEBUG(policyRef2b.buffer, policyRef2b.size, "policyRef2b");
    LOGBLOB_DEBUG(validationTicket2->digest.buffer, validationTicket2->digest.size, "validationTicket3");

    r = Esys_PolicyAuthorize(
        *ctx, **session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &policyDigest,
        &policyRef2b, nameKeySign, validationTicket2);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_PolicyAuthorize");
        return 1;
    }

// clean:
//     free(tobesigned);

    return r;

}

// int createIdKey(ESYS_CONTEXT **ctx, ESYS_TR *keyHandle, uint32_t persistent_index, 
//     TPM2B_DIGEST policyDigest){

//     if (ctx == NULL){
//         r = init(ctx, NULL);
//         if (r != 0){
//             LOG_ERROR("Error: initTCTI\n");
//             return 1;
//         }
//     }

//     r = Esys_CreatePrimary(*ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
//                            ESYS_TR_NONE, ESYS_TR_NONE,
//                            &inSensitivePrimaryKeyTemplate, &inPublicIdKeyTemplate,
//                            &outsideInfoEmpty, &creationPCREmpty, 
//                            keyHandle, &outPublic,
//                            &creationData, &creationHash,
//                            &creationTicket);
//     if (r != TSS2_RC_SUCCESS){
//         printf("Error: Esys_CreatePrimary IdKey\n");
//         return 1;
//     }

//     TPM2B_PUBLIC *outPublic;
//     outPublic = malloc(sizeof(TPM2B_PUBLIC));


//     r = Esys_ReadPublic(*ctx, *keyHandle, ESYS_TR_NONE, ESYS_TR_NONE,
//         ESYS_TR_NONE, &outPublic, NULL /* TPM2B_NAME */, NULL /* qualifiedName */); 
//     if (r != TSS2_RC_SUCCESS){
//         printf("Error: Esys_ReadPublic IdKey\n"); 
//         free(outPublic);
//         return 1; 
//     }

//     LOGBLOB_ERROR(outPublic->publicArea.unique.ecc.x.buffer, 
//         outPublic->publicArea.unique.ecc.x.size, "X");

//     LOGBLOB_ERROR(outPublic->publicArea.unique.ecc.y.buffer, 
//         outPublic->publicArea.unique.ecc.y.size, "Y");

//     uint8_t *buffer;
//     int bufferSize=
//         // 1 +
//         outPublic->publicArea.unique.ecc.x.size + 
//         outPublic->publicArea.unique.ecc.y.size;

//     buffer = malloc(bufferSize);
//     buffer[0] = 0x04;
//     memcpy(buffer+1, outPublic->publicArea.unique.ecc.x.buffer, 
//         outPublic->publicArea.unique.ecc.x.size);
//     memcpy(buffer+1+outPublic->publicArea.unique.ecc.x.size, 
//         outPublic->publicArea.unique.ecc.y.buffer, 
//         outPublic->publicArea.unique.ecc.y.size);

//     r = write_to_file(buffer, bufferSize, "public_id.key");
//     if (r != TSS2_RC_SUCCESS){
//         printf("Error: write_to_file public_id.key\n"); 
//         free(outPublic);
//         free(buffer);
//         return 1; 
//     }

//     free(outPublic);
//     free(buffer);

//     //  TPM2B_ENCRYPTED_SECRET

//     return 0;

// }


int createDerivationParent(ESYS_CONTEXT **ctx, ESYS_TR *keyHandleDerivationParent, 
    uint32_t persistent_index, uint8_t *rawKey, uint16_t rawKeySize, 
    TPM2B_DIGEST policyDigest){
    if (ctx == NULL){
        LOG_ERROR("Error: ctx == NULL\n");
        return 1;
        // r = init(ctx, NULL, NULL);
        // if (r != 0){
        //     LOG_ERROR("Error: initTCTI\n");
        //     return 1;
        // }
    }

/*******************************************************************
 *  1. Authenticate with the user/storage hierarchy
 *     Note: As described in the introduction this step is only
 *     mandatory if the storage hierarchy is secured with an
 *     authentication value. This step is included for completeness
 *     and the authentication value is set to "NULL".
 ******************************************************************/

    // TPM2B_AUTH authValue = {
    //     .size = 0,
    //     .buffer = {}
    // };

    // r = Esys_TR_SetAuth(*ctx, ESYS_TR_RH_OWNER, &authValue);
    // if (r != TSS2_RC_SUCCESS){
    //     printf("Error: Esys_TR_SetAuth\n");
    //     return 1;
    // }

/*******************************************************************
 *  2. Specify sensitive and public parameters of the to-be-created
 *  derivation parent object.
 ******************************************************************/

    /* Set previously defined authentication value */
    inSensitivePrimaryKeyTemplate.sensitive.userAuth = authValuePrimary;

    if(rawKeySize > 0){
        inSensitivePrimaryKeyTemplate.sensitive.data.size = rawKeySize;
        /* Set passed raw key data value */
        memcpy(inSensitivePrimaryKeyTemplate.sensitive.data.buffer, rawKey,
            inSensitivePrimaryKeyTemplate.sensitive.data.size);

        // printf("%s: ", "Key in parent TPM");
        // for (int i = 0; i < inSensitivePrimaryKeyTemplate.sensitive.data.size; i++){
        //     printf("%02x", inSensitivePrimaryKeyTemplate.sensitive.data.buffer[i]);
        // }
        // printf("\n");
    }
    else{
        printf("%s: ", "No specific key in parent TPM");
    }


    /* Initialize data structure for primary key's public 
     * parameters. Among other things, the key type (RSA) is defined
     * and some object attributes like a necessary authentication
     * for key usage, that the key may be used as decryption key and
     * that the key is bound to the specific TPM and hierarchy.
     */

    /* 
    Sign = 0, Decrypt=1, Restricted=1:
    Indicates that only the default schemes and modes of the key may be used In
    this specification, key with these properties is referred to as a Parent
    Key. Asymmetric keys and symmetric keys with these attributes are Storage
    Parents, and keyedHash objects with these attributes are Derivation Parents.
    The TPM only allows keys with these attributes to be used on objects that
    have a specific structure. For Storage Parents, use includes create, load,
    and activate credential.
    */

    /* 
     * Set previously defined policy digest as authentication value.
     */
    (&inPublicDerivationParentTemplate)->publicArea.authPolicy.size = policyDigest.size;
    memcpy(inPublicDerivationParentTemplate.publicArea.authPolicy.buffer,
      (const BYTE *)&policyDigest.buffer, policyDigest.size);

    LOGBLOB_DEBUG((&inPublicDerivationParentTemplate)->publicArea.authPolicy.buffer, 
    (&inPublicDerivationParentTemplate)->publicArea.authPolicy.size, "DERIVATION POLICY");

    if (policyDigest.size == 0){
        inPublicDerivationParentTemplate.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
        LOG_DEBUG("Attributes: %02x", inPublicDerivationParentTemplate.publicArea.objectAttributes);
    }


/*******************************************************************
 *  3. Execute ESAPI command to create primary key and authenticate
 *  with the key for usage.
 ******************************************************************/

    r = Esys_CreatePrimary(*ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitivePrimaryKeyTemplate, &inPublicDerivationParentTemplate,
                           &outsideInfoEmpty, &creationPCREmpty, 
                           keyHandleDerivationParent, &outPublic,
                           &creationData, &creationHash,
                           &creationTicket);
    
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_CreatePrimary\n");
        return 1;
    }
    else{
        LOG_DEBUG("Esys_CreatePrimary successful");
    }

    ESYS_TR newObjectHandle = ESYS_TR_NONE;
    r = Esys_EvictControl(*ctx, ESYS_TR_RH_OWNER,
        *keyHandleDerivationParent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        persistent_index, &newObjectHandle);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("failed to make key %02x persistent: %02x\n", 
            *keyHandleDerivationParent, r);
        return 1;
    }

    return 0;
}

int deriveUpdateKey(ESYS_CONTEXT **ctx, uint32_t persistent_index,
    uint8_t *label, uint16_t labelSize, uint8_t *context, uint16_t contextSize,
    ESYS_TR **derived_key_handle, ESYS_TR session){

    if (ctx == NULL){
        LOG_ERROR("Error: ctx == NULL\n");
        return 1;
        // r = init(ctx, NULL, NULL);
        // if (r != 0){
        //     printf("Error: initTCTI\n");
        //     return 1;
        // }
    }

    uint32_t pwdOrSession = ESYS_TR_NONE;

    if(session != ESYS_TR_NONE){
        LOG_DEBUG("session SET !!!");
        pwdOrSession = session;
    }

/*******************************************************************
 *  4. Create Update Key
 ******************************************************************/

    /* Initialize data structure for primary key's insensitive
     * parameters.
     */
    TPM2B_SENSITIVE_CREATE inSensitiveKU = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0},
            },
            .data = {
                .size = 0,
                .buffer = {0},
            },
        },
    };

    TPM2B_DIGEST uniqueKU = {
        .size = TPM2_SHA256_DIGEST_SIZE,
        .buffer = { 0 }
    };

    /* Add hash over FW and expected counter as input to KDF */
    inPublicDerivedApplicationKeyTemplate.unique.derive.label.size = labelSize;
    memcpy(inPublicDerivedApplicationKeyTemplate.unique.derive.label.buffer, label, 
        inPublicDerivedApplicationKeyTemplate.unique.derive.label.size);

    inPublicDerivedApplicationKeyTemplate.unique.derive.context.size = contextSize;
    memcpy(inPublicDerivedApplicationKeyTemplate.unique.derive.context.buffer, context, 
        inPublicDerivedApplicationKeyTemplate.unique.derive.context.size);

    TPM2B_TEMPLATE inPublicTemplateKU = { 0 };
    size_t offset = 0;

    // LOGBLOB_DEBUG(label, labelSize, "Label");

    LOGBLOB_DEBUG(inPublicDerivedApplicationKeyTemplate.unique.derive.label.buffer, 
        inPublicDerivedApplicationKeyTemplate.unique.derive.label.size, 
        "inPublicDerivedApplicationKeyTemplateLabel");

    r = Tss2_MU_TPMT_PUBLIC_DERIVE_Marshal(&inPublicDerivedApplicationKeyTemplate, 
        &inPublicTemplateKU.buffer[0], sizeof(TPMT_PUBLIC), &offset);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("Tss2_MU_TPMT_PUBLIC_DERIVE_Marshal FAILED! Response Code: 0x%x", r);
        return 1;
    } 
    inPublicTemplateKU.size = offset;

    LOGBLOB_DEBUG(inPublicTemplateKU.buffer, inPublicTemplateKU.size, "inPublicDerivedApplicationKeyTemplate");

    ESYS_TR keyHandleDerivationParent;
    r = Esys_TR_FromTPMPublic(*ctx, persistent_index, ESYS_TR_NONE , ESYS_TR_NONE, 
        ESYS_TR_NONE, &keyHandleDerivationParent);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_TR_FromTPMPublic");
        LOG_ERROR("Did you create the derivation parent first?");
        return r;
    }

    // uint32_t pwdOrSession = ESYS_TR_PASSWORD;
    if (session == ESYS_TR_NONE){
        LOG_DEBUG("session == ESYS_TR_NONE 2");
        r = Esys_TR_SetAuth(*ctx, keyHandleDerivationParent, &authValuePrimary);
        if (r != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_TR_SetAuth\n");
            return 1;
        }
        pwdOrSession = ESYS_TR_PASSWORD;
    }
    else{
        pwdOrSession = session;
        LOG_DEBUG("session set!!! %02x, %02x", session, pwdOrSession);
    }

    LOG_DEBUG("Esys_TR_FromTPMPublic: %02x", keyHandleDerivationParent);

    /* Define variables for the command's responses.*/
    TPM2B_PRIVATE *outPrivateKU;
    TPM2B_PUBLIC *outPublicKU;

    r = Esys_CreateLoaded(*ctx, keyHandleDerivationParent, pwdOrSession,
        ESYS_TR_NONE, ESYS_TR_NONE, &inSensitiveKU, &inPublicTemplateKU,
        *derived_key_handle, &outPrivateKU, &outPublicKU);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Esys_CreateLoaded");
        return 1;
    }

    return 0;
}

int createHMACTPM(ESYS_CONTEXT **ctx, uint16_t hashAlg, uint32_t key_handle,
    uint8_t *data, uint32_t dataSize, uint8_t *outputMac, size_t *outputMacSize){

    TPM2B_MAX_BUFFER *buffer;
    buffer = malloc(sizeof(TPM2B_MAX_BUFFER));
    buffer->size=dataSize;
    memcpy(buffer->buffer, data, dataSize);

    TPM2B_DIGEST *digestTPM;
    digestTPM = malloc(sizeof(TPM2B_DIGEST));

    LOGBLOB_DEBUG(data, dataSize, "Data to be hmaced");

    r = Esys_HMAC(*ctx, key_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        buffer, hashAlg, &digestTPM);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Error: Esys_HMAC\n");
        free(buffer);
        free(digestTPM);
        return 1;
    }

    LOGBLOB_DEBUG(digestTPM->buffer, digestTPM->size, "digestTPM");

    *outputMacSize = digestTPM->size;
    memcpy(outputMac, digestTPM->buffer, *outputMacSize);

    free(buffer);
    free(digestTPM);

    return 0;
}

void getCurrentPolicyDigest(ESYS_CONTEXT *ctx, ESYS_TR *session){
    TPM2B_DIGEST *policyDigest;
    policyDigest = malloc(sizeof(TPM2B_DIGEST));


    r = Esys_PolicyGetDigest(ctx, *session, ESYS_TR_NONE, ESYS_TR_NONE, 
        ESYS_TR_NONE, &policyDigest);
    if(r != 0){
        LOG_ERROR("Esys_PolicyGetDigest FAILED! Response Code : 0x%x\n", r);
        //return r;
    }
    LOGBLOB_ERROR(policyDigest->buffer, policyDigest->size, "policyDigest");
    free(policyDigest);
}

void cleanup(ESYS_CONTEXT **ctx, ESYS_TR handle){
    if (handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(*ctx, handle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup handle failed.");
        }
    }
}

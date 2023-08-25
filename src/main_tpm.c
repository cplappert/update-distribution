/*
 * ./src/swtpm/swtpm socket --tpm2 --server port=2321 --ctrl type=tcp,port=2322 --flags not-need-init --tpmstate dir="."
 */

#include <argp.h>
#include <stdbool.h>

#include "fileHandler.h"
#include "updateHandlerTpm.h"

#include <openssl/sha.h>
#include <openssl/pem.h>

#ifdef PERFORMANCE
#include <unistd.h> // For sleep
#include <sys/time.h> 
struct timespec start_all, end_all, start_send, end_send, start_policy_exec, end_policy_exec, start_policy_auth, end_policy_auth, start_derivation, end_derivation, start_hmac, end_hmac;
// float start_all_cpu, end_all_cpu, start_policy_auth_cpu, end_policy_auth_cpu, start_derivation_cpu, end_derivation_cpu, start_hmac_cpu, end_hmac_cpu;
#endif


/* For PolicySigned Callbacks */
// #include <termios.h>
// #include <unistd.h>
/* /For PolicySigned Callbacks */


#define LOGMODULE update
#include "util/log.h"

#define MAXREADSIZE                 2048
#define PERSISTENT_ID_KEY           0x81000000
#define PERSISTENT_BASE_KEY         0x81000001
#define PERSISTENT_BASE_KEY_PW      0x81000002

#define NV_INDEX_REVOCATION     0x1000000
#define NV_INDEX_SESSIONHASH    0x1000001

#define BUFFERSIZE                  13 //64 //32
#define NANOSECOND_DIVISOR          1000000
#define SECOND_MULTIPLIER           1000

/* Initialize the TCTI context.*/
// char *tcti_name = "device:/dev/tpm0";
/* Alternative for IBM simulator */
// char *tcti_name = "mssim:host=127.0.0.1,port=2321";
/* Alternative for SW TPM */
char *tcti_name = "swtpm:host=10.0.0.20,port=2321";

const char *argp_program_version = "0.5";
const char *argp_program_bug_address = "<your@email.address>";
static char doc[] = "Secure Software Update.";
static char args_doc[] = "[FILENAME]...";
static struct argp_option options[] = {
    /* Commands */
    { "provision", 'p', 0, 0, "Provision TPM with Derivation Parent."},
    { "createpolicies", 'c', 0, 0, "Create Update-specific Policies."},
    { "conditionalrekeying", 'a', 0, 0, "Conditional rekeying of the update signature to a MAC."},
    { "authorizeinstallation", 'b', 0, 0, "Authorize the installation of the update."},
    /* Parameters */
    { "session-hash", 'h', "FILE_PATH or STDIN", 0, "update data."},
    { "signature", 'i', "FILE_PATH or STDIN", 0, "A Signature."},
    { "update-signature", 'j', "FILE_PATH or STDIN", 0, "A Update Signature."},
    { "update-data", 'u', "FILE_PATH or STDIN", 0, "update data."},
    { "ecu-ids", 'e', "FILE_PATH or STDIN", 0, "Key Handle."},
    // { "verify", 'v', "FILE_PATH or STDIN", 0, "Verify a loaded key."},
    // { "digest", 'd', "FILE_PATH or STDIN", 0, "A Digest."},
    { "pem-key", 'k', "FILE_PATH or STDIN", 0, "A PEM key created with OpenSSL."},
    { "nonce", 'n', "FILE_PATH or STDIN", 0, "A Nonce from the ECU."},
    { "out1", 'o', "FILE_PATH or STDIN", 0, "A file path for output1."},
    { "out2", 'q', "FILE_PATH or STDIN", 0, "A file path for output2."},
    { "raw-derivation-key", 'r', "FILE_PATH or STDIN", 0, "A common base secret between TPM and ECU."},
    // { "signature", 's', "FILE_PATH or STDIN", 0, "A Signature."},
    { "secret", 's', "FILE_PATH or STDIN", 0, "A secret key."},
    { "template-hash", 't', "FILE_PATH or STDIN", 0, "The Template-Hash."},
    { 0 } 
};

struct arguments {
    enum { CHARACTER_MODE, WORD_MODE, LINE_MODE } mode;
    enum { NONE, PROVISION, CREATE_POLICIES, CONDITIONAL_REKEYING, AUTHORIZE_INSTALLATION } command;
        // AUTHORIZE_UPDATE, VERIFY_LOADED_KEY, TEST_POLICY_SIGNED } command;
    char* filePath;
    char* filePathDigest;
    char* filePathPEMKey;
    char* filePathSignature;
    char* filePathUpdateSignature;
    char* filePathSecret;
    char* filePathTemplateHash;
    char* filePathNonce;
    char* filePathOut1;
    char* filePathOut2;
    char* filePathUpdateData;
    int mutexCmdCtr;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
        case 'a':
            arguments->command = CONDITIONAL_REKEYING; 
            arguments->mutexCmdCtr += 1;
            break;
        case 'b':
            arguments->command = AUTHORIZE_INSTALLATION; 
            arguments->mutexCmdCtr += 1;
            break;
        case 'c':
            arguments->command = CREATE_POLICIES; 
            arguments->mutexCmdCtr += 1;
            break;
        case 'e': 
            arguments->filePath = arg;
            break;
        case 'h':  
            arguments->filePathDigest = arg;
            break;
        case 'k':  
            arguments->filePathPEMKey = arg;
            break;
        case 'i':
            arguments->filePathSignature = arg;
            break;
        case 'j':
            arguments->filePathUpdateSignature = arg;
            break;
        case 'n': 
            arguments->filePathDigest = arg;
            break;
        case 'o': 
            arguments->filePathOut1 = arg;
            break;
        case 'p':
            arguments->command = PROVISION; 
            // arguments->filePath = arg;
            arguments->mutexCmdCtr += 1;
            break;
        case 'q': 
            arguments->filePathOut2 = arg;
            break;
        case 'r':
            arguments->filePath = arg;
            break;
        case 's': 
            arguments->filePathSecret = arg;
            break;
        case 't':
            arguments->filePathTemplateHash = arg;
            break;
        case 'u':
            arguments->filePathUpdateData = arg;
            break;
        case ARGP_KEY_ARG: return 0;
        default: return ARGP_ERR_UNKNOWN;
    } 
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

int main(int argc, char *argv[])
{

    int rc;
    struct arguments arguments;
    arguments.mutexCmdCtr = 0;
    arguments.filePath = "";
    arguments.filePathPEMKey = "";
    arguments.filePathSignature = "";
    arguments.filePathUpdateSignature = "";
    arguments.filePathDigest = "";
    arguments.filePathTemplateHash = "";
    arguments.filePathSecret = "";
    arguments.filePathUpdateData = "";
    arguments.filePathOut1 = "";
    arguments.filePathOut2 = "";

#ifdef PERFORMANCE
    char *rkpString, *iapString;
    rkpString = malloc(MAXREADSIZE);
    iapString = malloc(MAXREADSIZE);
    memset(rkpString, '\0', 1);
    memset(iapString, '\0', 1);
#endif

    ESYS_TR *session_handle, *session, *derived_key_handle, *challenge_key_handle1;
    ESYS_TR loaded_key_handle = ESYS_TR_NONE;
    ESYS_TR key_handle = ESYS_TR_NONE;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    // ESYS_TR challenge_key_handle1 = ESYS_TR_NONE;
    // session_handle = malloc(sizeof(ESYS_TR));
    // *session_handle = ESYS_TR_NONE;

    session_handle = malloc(sizeof(ESYS_TR));
    *session_handle = ESYS_TR_NONE;
    session = malloc(sizeof(ESYS_TR));
    *session = ESYS_TR_NONE;
    derived_key_handle = malloc(sizeof(ESYS_TR));
    *derived_key_handle = ESYS_TR_NONE;
    challenge_key_handle1 = malloc(sizeof(ESYS_TR));
    *challenge_key_handle1 = ESYS_TR_NONE;

    // TPM2B_DIGEST *outHMAC;
    // outHMAC = malloc(sizeof(TPM2B_DIGEST));
    uint8_t *rawKey = NULL, *pemKey = NULL, *authIn = NULL;

    TPM2B_DIGEST *policyDigest, *outputMac, /* *policySignature,*/ *updateDataHash, 
        *templateHash, *sessionHash;
    policyDigest = malloc(sizeof(TPM2B_DIGEST));
    outputMac = malloc(sizeof(TPM2B_DIGEST));
    outputMac->size = 0;
    // policySignature = malloc(sizeof(TPM2B_DIGEST));
    updateDataHash = malloc(sizeof(TPM2B_DIGEST));
    templateHash = malloc(sizeof(TPM2B_DIGEST));
    sessionHash = malloc(sizeof(TPM2B_DIGEST));

    uint8_t *policySignature, *updateSignature;
    policySignature = malloc(MAXREADSIZE);
    updateSignature = malloc(MAXREADSIZE);
    int policySignatureSize=0;
    int updateSignatureSize=0;


    TPM2B_NONCE *nonceTPM;
    nonceTPM = malloc(sizeof(TPM2B_NONCE));
    nonceTPM->size=0;

    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};

    // uint8_t *updateBundle = NULL, *nonce = NULL, *templateHashOLD = NULL, 
    //     *der_signature = NULL, *raw_digest = NULL, *rawKey = NULL, 
    //     *pemKey = NULL;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if(arguments.mutexCmdCtr > 1){
        LOG_ERROR("The Commands --create, --authorize-update, and --verify are mutual exclusive.\n");
        rc = 1;
        goto clean;
    }

    /* Initialize variables for context.*/
    ESYS_CONTEXT *ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

    rc = Tss2_TctiLdr_Initialize(tcti_name, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS){
        printf("Error: Tss2_TctiLdr_Initialize\n");
        return 1;
    }

    rc = init(&ctx, tcti_ctx, tcti_name);
    if(rc!=0){
        LOG_ERROR("Error: %s\n", "init");
        goto clean;
    }

    TPM2B_NONCE nonceCaller = {
        .size = 32,
        .buffer = {11, 12, 13, 14, 15, 16, 17, 18, 19, 11,
                   21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                   21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                   21, 22}
    };

    TPM2B_NV_PUBLIC publicNvInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex = 0 /* TO BE SET */, // TPM2_NV_INDEX_FIRST,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_WRITE_STCLEAR |
                TPMA_NV_READ_STCLEAR |
                TPMA_NV_AUTHREAD |
                TPMA_NV_OWNERREAD
                ),
            .authPolicy = {
                 .size = 0,
                 .buffer = {},
             },
            .dataSize = 0 /* TO BE SET */,
        }
    };

    if(arguments.command == PROVISION){
        LOG_INFO("%s", "Call this from the backend, e.g., via remote TCTI.");

        if (strlen(arguments.filePath) == 0){
            LOG_ERROR("%s\n", "Parameter for Derivation Key is missing. Please specify with 'raw-derivation-key' or 'r'");
            goto clean;
        }
        if (strlen(arguments.filePathPEMKey) == 0){
            LOG_ERROR("%s\n", "Parameter for Backend Key is missing. Please specify with 'pem-key' or 'k'");
            goto clean;
        }

        if (strlen(arguments.filePathDigest) == 0){
            LOG_ERROR("%s\n", "Expected session hash is missing. Please specify with 'session-hash' or 'h'");
            rc = 1;
            goto clean;
        }

        int size_raw_key, size_pem_key;
        rawKey = malloc(MAXREADSIZE);
        pemKey = malloc(MAXREADSIZE);

        TPM2B_DIGEST sessionHash;

        rc = read_from_file(sessionHash.buffer, MAXREADSIZE, (int*) &sessionHash.size, arguments.filePathDigest);
        if(rc!=0){
            LOG_ERROR("%s\n", "read_from_file sessionHash");
            goto clean;
        }

        rc = read_from_file(rawKey, MAXREADSIZE, &size_raw_key, arguments.filePath);
        if(rc!=0){
            LOG_ERROR("%s\n", "read_from_file rawKey");
            goto clean;
        }

        uint16_t alg = TPM2_ALG_RSA;
        if (strstr(arguments.filePathPEMKey, "ecc") != NULL) {
            alg = TPM2_ALG_ECC;
        }

        rc = load_external_key_from_pem(&ctx, arguments.filePathPEMKey, alg,
            &loaded_key_handle);
        if(rc!=0){
            LOG_ERROR("%s\n", "load_external_key_from_pem");
            goto clean;
        }

        TPM2_SE session_type = TPM2_SE_TRIAL;

        // LOGBLOB_ERROR(policyDigest->buffer, policyDigest->size, "policyDigestOB");

        rc = create_authorization_policy(&ctx, nonceCaller, 
            session_type, &session_handle, loaded_key_handle, &policyDigest);
        if(rc!=0){
            LOG_ERROR("%s\n", "get_template_session_digest");
            goto clean;
        }

        // LOGBLOB_ERROR(policyDigest->buffer, policyDigest->size, "policyDigestOA");

        rc = createDerivationParent(&ctx, &key_handle, 
            PERSISTENT_BASE_KEY, rawKey, size_raw_key, *policyDigest);
        if(rc!=0){
            LOG_ERROR("%s\n", "createDerivationParent");
            goto clean;
        }

        policyDigest->size=0; // User Auth Key
        rc = createDerivationParent(&ctx, &key_handle, 
            PERSISTENT_BASE_KEY_PW, rawKey, size_raw_key, *policyDigest);
        if(rc!=0){
            LOG_ERROR("%s\n", "createDerivationParent");
            goto clean;
        }

        // Gets 0x902 // Must use Esys_EvictControl
        // rc = createIdKey(&ctx, &key_handle, PERSISTENT_ID_KEY, *policyDigest);
        // if(rc!=0){
        //     LOG_ERROR("%s\n", "createDerivationParent");
        //     goto clean;
        // }

        // rc = Esys_EvictControl(&ctx, &key_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, );
        // if(rc!=0){
        //     LOG_ERROR("%s\n", "createDerivationParent");
        //     goto clean;
        // }        
        
        /* Revocation Index */
        publicNvInfo.nvPublic.nvIndex = NV_INDEX_REVOCATION;
        publicNvInfo.nvPublic.attributes = publicNvInfo.nvPublic.attributes | (TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT);
        publicNvInfo.nvPublic.dataSize = 8;
        rc = Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
            ESYS_TR_NONE, ESYS_TR_NONE, NULL, &publicNvInfo, &nvHandle);
        if(rc!=0){
            LOG_ERROR("%s\n", "Esys_NV_DefineSpace");
            goto clean;
        }

        rc = Esys_NV_Increment(ctx, ESYS_TR_RH_OWNER, nvHandle, ESYS_TR_PASSWORD,
            ESYS_TR_NONE, ESYS_TR_NONE);
        if(rc!=0){
            LOG_ERROR("%s\n", "Esys_NV_Increment");
            goto clean;
        }

        /* SessionHash Index */
        publicNvInfo.nvPublic.nvIndex = NV_INDEX_SESSIONHASH;
        publicNvInfo.nvPublic.attributes = publicNvInfo.nvPublic.attributes &~ (TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT);
        publicNvInfo.nvPublic.dataSize = sessionHash.size;

        rc = Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
            ESYS_TR_NONE, ESYS_TR_NONE, NULL, &publicNvInfo, &nvHandle);
        if(rc!=0){
            LOG_ERROR("%s\n", "Esys_NV_DefineSpace");
            goto clean;
        }

        TPM2B_MAX_NV_BUFFER nvData;
        nvData.size = sessionHash.size;
        memcpy(nvData.buffer, sessionHash.buffer, nvData.size);

        LOGBLOB_DEBUG(nvData.buffer, nvData.size, "nvData");

        rc = Esys_NV_Write(ctx, nvHandle, nvHandle, ESYS_TR_PASSWORD,
            ESYS_TR_NONE, ESYS_TR_NONE, &nvData, 0 /* Offset */);
        if(rc!=0){
            LOG_ERROR("%s\n", "Esys_NV_DefineSpace");
            goto clean;
        }

        TPM2B_MAX_NV_BUFFER *data;
        data = malloc(sizeof(TPM2B_MAX_NV_BUFFER));
        rc = Esys_NV_Read(ctx, nvHandle,nvHandle, ESYS_TR_PASSWORD,
            ESYS_TR_NONE, ESYS_TR_NONE, 32, 0 /* Offset */, &data);
        if(rc!=0){
                LOG_ERROR("%s\n", "Esys_NV_Read");
                return 1;
            }
        LOGBLOB_DEBUG(data->buffer, data->size, "Esys_NV_Read");

        printf("%s\n", "Key Provision successful!");
    }

    if(arguments.command == CREATE_POLICIES){
        LOG_INFO("%s", "Call this from the backend");

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_all);

        sleep(1);

        clock_gettime(CLOCK_MONOTONIC_RAW, &end_all);

        char *testString;
        testString = malloc(MAXREADSIZE);
        memset(testString, '\0', 1);

        snprintf(testString + strlen(testString), BUFFERSIZE, "%f,",
            ((end_all.tv_sec - start_all.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_all.tv_nsec - start_all.tv_nsec) / (double) NANOSECOND_DIVISOR));

        printf("testString: %s\n", testString);

        #endif



        if (strlen(arguments.filePathDigest) == 0){
            LOG_ERROR("%s\n", "Expected session hash is missing. Please specify with 'session-hash' or 'h'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathTemplateHash) == 0){
            LOG_ERROR("%s\n", "Parameter for Template Hash is missing. Please specify with 'template-hash' or 't'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePath) == 0){
            LOG_ERROR("%s\n", "Parameter for ecu ids is missing. Please specify with 'ecu-ids' or 'e'");
            rc = 1;
            goto clean;
        }

        TPM2B_DIGEST *templateHash, *sessionHash;
        templateHash = malloc(sizeof(TPM2B_DIGEST));
        sessionHash = malloc(sizeof(TPM2B_DIGEST));

        rc = read_from_file(templateHash->buffer, MAXREADSIZE, (int*) &templateHash->size, arguments.filePathTemplateHash);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file templateHash");
            return 1;
        }
        else{
            if (templateHash->size != (SHA256_DIGEST_LENGTH)){
                LOG_ERROR("Error: %s has wrong size of %d\n", "templateHash", templateHash->size);
                return 1;
            }
        }

        rc = read_from_file(sessionHash->buffer, MAXREADSIZE, (int*) &sessionHash->size, arguments.filePathDigest);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file sessionHash");
            return 1;
        }
        else{
            if (sessionHash->size != (SHA256_DIGEST_LENGTH)){
                LOG_ERROR("Error: %s has wrong size of %d\n", "sessionHash", sessionHash->size);
                return 1;
            }
        }

        // LOGBLOB_ERROR(templateHash->buffer, templateHash->size, "templateHash");
        // LOGBLOB_ERROR(sessionHash->buffer, sessionHash->size, "sessionHash");

        rc = Esys_TR_FromTPMPublic(ctx, NV_INDEX_SESSIONHASH, ESYS_TR_NONE, 
            ESYS_TR_NONE, ESYS_TR_NONE, &nvHandle);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_TR_FromTPMPublic: Was the index defined?");
            return 1;
        }

        *session = ESYS_TR_NONE;
        rc = executeRKP(&ctx, nonceCaller, &session, templateHash, sessionHash, 
            nvHandle, TPM2_SE_TRIAL /* TPM2_SE_POLICY */, &policyDigest
#ifdef PERFORMANCE
            , NULL
#endif
); 
        if(rc!=0){
            LOG_ERROR("createKDP"); 
            goto clean;
        }

        rc = Esys_FlushContext(ctx, *session);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_FlushContext: session");
            return 1;
        }
        *session = ESYS_TR_NONE;

        LOGBLOB_DEBUG(policyDigest->buffer, policyDigest->size, "policyRKPDigest Create");

        rc = write_to_file(policyDigest->buffer, policyDigest->size, "data/rkp.digest");
        if(rc!=0){
            printf("Error: %s\n", "write_to_file RKP");
            return 1;
        }

        rc = Esys_TR_FromTPMPublic(ctx, NV_INDEX_REVOCATION,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &nvHandle);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_TR_FromTPMPublic: Was the index defined?");
            return 1;
        }

        rc = read_from_file(sessionHash->buffer, MAXREADSIZE, (int*) &sessionHash->size, 
            arguments.filePath);
        if(rc!=0){
            LOG_ERROR("%s\n", "read_from_file ecu-ids");
            goto clean;
        }

        rc = deriveUpdateKey(&ctx, PERSISTENT_BASE_KEY_PW, &sessionHash->buffer[0],
            1, NULL, 0, &derived_key_handle, ESYS_TR_NONE);
        if(rc!=0){
            LOG_ERROR("deriveUpdateKey");
            goto clean;
        }

        rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, &nonceCaller, TPM2_SE_TRIAL, &symmetric, 
            TPM2_ALG_SHA256, session);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_StartAuthSession");
            return 1;
        }

        policyDigest->size=0;
        rc = executeIAP(&ctx, nonceCaller, &session, templateHash, nvHandle, 
            *derived_key_handle, TPM2_SE_TRIAL /* TPM2_SE_POLICY */ , *outputMac, 
            *nonceTPM, &policyDigest
#ifdef PERFORMANCE
            , NULL
#endif
        ); 
        if(rc!=0){
            LOG_ERROR("createIAP"); 
            goto clean;
        }

        rc = Esys_FlushContext(ctx, *derived_key_handle);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_FlushContext: derived_key_handle");
            return 1;
        }
        *derived_key_handle = ESYS_TR_NONE;

        rc = Esys_FlushContext(ctx, *session);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_FlushContext: session");
            return 1;
        }
        *session = ESYS_TR_NONE;

        LOGBLOB_DEBUG(policyDigest->buffer, policyDigest->size, "policyIAPDigest Create");
        rc = write_to_file(policyDigest->buffer, policyDigest->size, "data/iap.digest");
        if(rc!=0){
            printf("Error: %s\n", "write_to_file IAP");
            return 1;
        }

        printf("Success! Policies written to %s, and %s\n", "data/rkp.digest", "data/iap.digest");

    }

    /* BB1 */
    if(arguments.command == CONDITIONAL_REKEYING){

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_all);
        // start_all_cpu = clock() / CLOCKS_PER_SEC;
        #endif

        if (strlen(arguments.filePathSignature) == 0){
            LOG_ERROR("%s\n", "Parameter for policy signature is missing. Please specify with 'signature' or 'i'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathTemplateHash) == 0){
            LOG_ERROR("%s\n", "Parameter for Template Hash is missing. Please specify with 'template-hash' or 't'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathDigest) == 0){
            LOG_ERROR("%s\n", "Expected session hash is missing. Please specify with 'session-hash' or 'h'");
            rc = 1;
            goto clean;
        }
        if (strlen(arguments.filePathPEMKey) == 0){
            LOG_ERROR("%s\n", "Parameter for Public Key is missing. Please specify with 'pem-key' or 'k'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathUpdateData) == 0){
            LOG_ERROR("%s\n", "Update Data is missing. Please specify with 'update-data' or 'u'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathUpdateSignature) == 0){
            LOG_ERROR("%s\n", "Parameter for update data signature is missing. Please specify with 'update-signature' or 'j'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathOut1) == 0){
            LOG_ERROR("%s\n", "File Path for out hmac is missing. Please specify with 'out1' or 'o'");
            rc = 1;
            goto clean;
        }

        rc = read_from_file(policySignature, MAXREADSIZE, (int*) &policySignatureSize, arguments.filePathSignature);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file policySignature");
            goto clean;
        }

        rc = read_from_file(updateSignature, MAXREADSIZE, (int*) &updateSignatureSize, arguments.filePathUpdateSignature);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file policySignature");
            goto clean;
        }

        rc = read_from_file(templateHash->buffer, MAXREADSIZE, (int*) &templateHash->size, arguments.filePathTemplateHash);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file templateHash");
            return 1;
        }

        // LOGBLOB_ERROR(templateHash->buffer, templateHash->size, "templateHash");

        rc = read_from_file(sessionHash->buffer, MAXREADSIZE, (int*) &sessionHash->size, arguments.filePathDigest);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file sessionHash");
            goto clean;
        }

        rc = read_from_file(updateDataHash->buffer, MAXREADSIZE, (int*) &updateDataHash->size, arguments.filePathUpdateData);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file updateDataHash");
            goto clean;
        }

        uint16_t alg = TPM2_ALG_RSA;
        if (strstr(arguments.filePathPEMKey, "ecc") != NULL) {
            alg = TPM2_ALG_ECC;
        }

        rc = load_external_key_from_pem(&ctx, arguments.filePathPEMKey, alg,
            &loaded_key_handle);
        if(rc!=0){
            LOG_ERROR("%s\n", "load_external_key_from_pem");
            goto clean;
        }

        LOGBLOB_DEBUG(updateSignature, updateSignatureSize, "readUpdateSig: ");
        LOG_DEBUG("loaded_key_handle 1: %02x", loaded_key_handle);

        rc = verifySignature(&ctx, loaded_key_handle, updateSignature, updateSignatureSize, *updateDataHash, alg
#ifdef PERFORMANCE 
        , rkpString
#endif
        );
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("VerifySignature");
            goto clean;
        }

        // LOGBLOB_ERROR(sessionHash->buffer, sessionHash->size, "sessionHash");

        rc = Esys_TR_FromTPMPublic(ctx, NV_INDEX_SESSIONHASH, ESYS_TR_NONE, 
            ESYS_TR_NONE, ESYS_TR_NONE, &nvHandle);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_TR_FromTPMPublic: Was the index defined?");
            goto clean;
        }
        
        policyDigest->size = 0;
        *session = ESYS_TR_NONE; // Insert again?

        // #ifdef PERFORMANCE
        // char *rkpString;
        // rkpString = malloc(MAXREADSIZE);
        // #endif

        rc = executeRKP(&ctx, nonceCaller, &session, templateHash, sessionHash, 
            nvHandle, TPM2_SE_POLICY /* TPM2_SE_TRIAL */, &policyDigest
#ifdef PERFORMANCE 
            , rkpString
#endif
        ); 
        if(rc!=0){
            LOG_ERROR("executeRKP"); 
            goto clean;
        }

        LOGBLOB_DEBUG(policyDigest->buffer, policyDigest->size, "policyRKPDigest Execute");

        // LOG_ERROR("%s: %02x", "loaded_key_handle 1", loaded_key_handle);



        // LOG_ERROR("%s: %02x", "loaded_key_handle 2", loaded_key_handle);

        // uint8_t policyRefStruct[5] = {0x31, 0x32, 0x33, 0x34, 0x35};
        // size_t policyRefSize = 0;

        LOGBLOB_DEBUG(policySignature, policySignatureSize, "readPolicySig: ");

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_policy_auth);
        // start_policy_auth_cpu = clock() / CLOCKS_PER_SEC;
        #endif

        rc = authorizePolicy(&ctx, &session, loaded_key_handle, policySignature, 
            policySignatureSize, policyDigest->buffer, policyDigest->size, NULL /* &policyRefStruct[0] */, 
            0 /* policyRefSize */, alg);
        if(rc!=0){
            LOG_ERROR("authorizePolicy");
            goto clean;
        }

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_policy_auth);
        // end_policy_auth_cpu = clock() / CLOCKS_PER_SEC;
        #endif

        rc = Esys_FlushContext(ctx, loaded_key_handle);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_FlushContext: loaded_key_handle");
            goto clean;
        }
        loaded_key_handle = ESYS_TR_NONE;

        LOG_DEBUG("%s: %02x", "sessionO", *session);

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_derivation);
        // start_derivation_cpu = clock() / CLOCKS_PER_SEC;
        #endif

        rc = deriveUpdateKey(&ctx, PERSISTENT_BASE_KEY, updateDataHash->buffer,
            updateDataHash->size, NULL, 0, &derived_key_handle, *session);
        if(rc!=0){
            LOG_ERROR("deriveUpdateKey");
            goto clean;
        }

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_derivation);
        // end_derivation_cpu = clock() / CLOCKS_PER_SEC;
        #endif

        outputMac = malloc(sizeof(TPM2B_DIGEST));
        outputMac->size=0;

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_hmac);
        // start_hmac_cpu = clock() / CLOCKS_PER_SEC;
        #endif

        rc = createHMACTPM(&ctx, ALG_SHA256, *derived_key_handle,
            updateDataHash->buffer, updateDataHash->size, outputMac->buffer, 
            (size_t *) &outputMac->size);
        if(rc!=0){
            LOG_ERROR("createHMACTPM");
            goto clean;
        }

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_hmac);
        // end_hmac_cpu = clock() / CLOCKS_PER_SEC;
        #endif

        rc = Esys_FlushContext(ctx, *session);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_FlushContext: session");
            goto clean;;
        }
        *session = ESYS_TR_NONE;

        rc = Esys_FlushContext(ctx, *derived_key_handle);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_FlushContext: derived_key_handle");
            goto clean;
        }
        *derived_key_handle = ESYS_TR_NONE;

        LOGBLOB_DEBUG(outputMac->buffer, outputMac->size, "outputMac");

        rc = write_to_file(outputMac->buffer, outputMac->size, arguments.filePathOut1);
        if(rc!=0){
            LOG_ERROR("Error: %s\n", "write_to_file outputMac");
            goto clean;
        }

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_all);
        // end_all_cpu = clock() / CLOCKS_PER_SEC;
        size_t bufferSize = BUFFERSIZE;

        snprintf(rkpString + strlen(rkpString), bufferSize, "%f,",
            ((end_all.tv_sec - start_all.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_all.tv_nsec - start_all.tv_nsec) / (double) NANOSECOND_DIVISOR));

        snprintf(rkpString + strlen(rkpString), bufferSize, "%f,",
            ((end_policy_auth.tv_sec - start_policy_auth.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_policy_auth.tv_nsec - start_policy_auth.tv_nsec) / (double) NANOSECOND_DIVISOR));

        snprintf(rkpString + strlen(rkpString), bufferSize, "%f,",
            ((end_derivation.tv_sec - start_derivation.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_derivation.tv_nsec - start_derivation.tv_nsec) / (double) NANOSECOND_DIVISOR));

        snprintf(rkpString + strlen(rkpString), bufferSize, "%f\n",
            ((end_hmac.tv_sec - start_hmac.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_hmac.tv_nsec - start_hmac.tv_nsec) / (double) NANOSECOND_DIVISOR));

        rc = append_to_file(rkpString, strlen(rkpString), "rkp.perf");
        if(rc!=0){
            LOG_ERROR("Error: %s\n", "append_to_file rkpString");
            goto clean;
        }

        #endif

        // printf("Success! Written MAC to %s\n", arguments.filePathOut);

    }

    /* BB2 */
    if(arguments.command == AUTHORIZE_INSTALLATION){

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_all);
        #endif

        if (strlen(arguments.filePathOut1) == 0){
            LOG_ERROR("%s\n", "File Path for out nonce is missing. Please specify with 'out1' or 'o'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathOut2) == 0){
            LOG_ERROR("%s\n", "File Path for out hmac is missing. Please specify with 'out2' or 'q'");
            rc = 1;
            goto clean;
        }

        rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, &nonceCaller, TPM2_SE_POLICY, &symmetric, 
            TPM2_ALG_SHA256, session);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_StartAuthSession");
            goto clean;
        }

        rc = Esys_TRSess_GetNonceTPM(ctx, *session, &nonceTPM);
        if(rc!=0){
            LOG_ERROR("Esys_TRSess_GetNonceTPM"); 
            goto clean;
        }

        LOGBLOB_TRACE(nonceTPM->buffer, nonceTPM->size, "nonceTPM");

        rc = write_to_file(nonceTPM->buffer, nonceTPM->size, arguments.filePathOut1);
        if(rc!=0){
            LOG_ERROR("Error: %s\n", "write_to_file nonceTPM");
            goto clean;
        }

        if (strlen(arguments.filePathSignature) == 0){
            LOG_ERROR("%s\n", "Parameter for signature is missing. Please specify with 'signature' or 'i'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathPEMKey) == 0){
            LOG_ERROR("%s\n", "Parameter for Public Key is missing. Please specify with 'pem-key' or 'k'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathTemplateHash) == 0){
            LOG_ERROR("%s\n", "Parameter for Template Hash is missing. Please specify with 'template-hash' or 't'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePath) == 0){
            LOG_ERROR("%s\n", "Parameter for ECU IDs is missing. Please specify with 'ecu-ids' or 'e'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathDigest) == 0){
            LOG_ERROR("%s\n", "Parameter for ECU nonce is missing. Please specify with 'nonce' or 'n'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathUpdateData) == 0){
            LOG_ERROR("%s\n", "Update Data is missing. Please specify with 'update-data' or 'u'");
            rc = 1;
            goto clean;
        }

        rc = read_from_file(policySignature, MAXREADSIZE, (int*) &policySignatureSize, arguments.filePathSignature);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file policySignature");
            goto clean;
        }

        rc = read_from_file(templateHash->buffer, MAXREADSIZE, (int*) &templateHash->size, arguments.filePathTemplateHash);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file templateHash");
            goto clean;
        }

        /* sessionHash = ecu_ids*/
        rc = read_from_file(sessionHash->buffer, MAXREADSIZE, (int*) &sessionHash->size, arguments.filePath);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file ecu_ids");
            goto clean;;
        }

        LOGBLOB_DEBUG(sessionHash->buffer, sessionHash->size, "ecu_ids");

        rc = deriveUpdateKey(&ctx, PERSISTENT_BASE_KEY_PW, &sessionHash->buffer[0],
            1, NULL, 0, &challenge_key_handle1, ESYS_TR_NONE /* no session */);
        if(rc!=0){
            LOG_ERROR("deriveUpdateKey");
            goto clean;
        }

        rc = Esys_TR_FromTPMPublic(ctx, NV_INDEX_REVOCATION, ESYS_TR_NONE, 
            ESYS_TR_NONE, ESYS_TR_NONE, &nvHandle);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_TR_FromTPMPublic: Was the index defined?");
            goto clean;
        }

        char *line = NULL;  /* forces getline to allocate with malloc */
        char *line2;
        size_t len = 0;     /* ignored when line = NULL */
        ssize_t read;

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_send);
        #endif

        printf("Response Input: ");
        read = getline(&line, &len, stdin)-1;
        line2 = malloc(read);
        strncpy(line2, line, read);
        free (line);  /* free memory allocated by getline */

        strncpy(line2, "main-tpm-mac-ecu-c.tmp", read+1);

        LOGBLOB_TRACE(outputMac->buffer, outputMac->size, "inputMac");

        rc = read_from_file(outputMac->buffer, MAXREADSIZE, 
            (int*) &outputMac->size, line2);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file authIn2");
            free (line2);
            goto clean;
        }
        free (line2);

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_send);
        #endif

        LOGBLOB_TRACE(outputMac->buffer, outputMac->size, "inputMac");

        policyDigest->size = 0;
        rc = executeIAP(&ctx, nonceCaller, &session, templateHash, nvHandle, 
            *challenge_key_handle1, TPM2_SE_POLICY /* TPM2_SE_TRIAL */, *outputMac,
            *nonceTPM, &policyDigest
#ifdef PERFORMANCE
            , iapString
#endif
        ); 
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("executeIAP");
            goto clean;
        }

        rc = Esys_FlushContext(ctx, *challenge_key_handle1);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_FlushContext: challenge_key_handle1");
            goto clean;
        }
        *challenge_key_handle1 = ESYS_TR_NONE;

        LOGBLOB_TRACE(policyDigest->buffer, policyDigest->size, "policyIAPDigest Execute");

        uint16_t alg = TPM2_ALG_RSA;
        if (strstr(arguments.filePathPEMKey, "ecc") != NULL) {
            alg = TPM2_ALG_ECC;
        }

        rc = load_external_key_from_pem(&ctx, arguments.filePathPEMKey, alg,
            &loaded_key_handle);
        if(rc!=0){
            LOG_ERROR("%s\n", "load_external_key_from_pem");
            goto clean;
        }

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_policy_auth);
        #endif

        rc = authorizePolicy(&ctx, &session, loaded_key_handle, policySignature, 
            policySignatureSize, policyDigest->buffer, policyDigest->size, NULL /* &policyRefStruct[0] */, 
            0 /* policyRefSize */, alg);
        if(rc!=0){
            LOG_ERROR("authorizePolicy");
            goto clean;
        }

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_policy_auth);
        #endif

        rc = Esys_FlushContext(ctx, loaded_key_handle);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_FlushContext: loaded_key_handle");
            goto clean;
        }
        loaded_key_handle = ESYS_TR_NONE;

        rc = read_from_file(updateDataHash->buffer, MAXREADSIZE, 
            (int*) &updateDataHash->size, arguments.filePathUpdateData);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file ecu_ids");
            goto clean;
        }

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_derivation);
        #endif

        rc = deriveUpdateKey(&ctx, PERSISTENT_BASE_KEY, updateDataHash->buffer,
            updateDataHash->size, NULL, 0, &derived_key_handle, *session);
        if(rc!=0){
            LOG_ERROR("deriveUpdateKey");
            goto clean;
        }

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_derivation);
        #endif

        rc = read_from_file(nonceTPM->buffer, MAXREADSIZE, (int*) &nonceTPM->size, arguments.filePathDigest);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file nonceECU");
            goto clean;
        }
        LOGBLOB_TRACE(nonceTPM->buffer, nonceTPM->size, "nonceECU");

        // outputMac = malloc(sizeof(TPM2B_DIGEST));
        outputMac->size=0;

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_hmac);
        #endif
        rc = createHMACTPM(&ctx, ALG_SHA256, *derived_key_handle, nonceTPM->buffer, 
            nonceTPM->size, outputMac->buffer, (size_t *) &outputMac->size);
        if(rc!=0){
            LOG_ERROR("createHMACTPM");
            goto clean;
        }
        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_hmac);
        #endif

        rc = Esys_FlushContext(ctx, *derived_key_handle);
        if (rc != TSS2_RC_SUCCESS){
            LOG_ERROR("Esys_FlushContext: derived_key_handle");
            goto clean;
        }
        *derived_key_handle = ESYS_TR_NONE;

        LOGBLOB_TRACE(outputMac->buffer, outputMac->size, "outputMac");

        rc = write_to_file(outputMac->buffer, outputMac->size, arguments.filePathOut2);
        if(rc!=0){
            LOG_ERROR("Error: %s\n", "write_to_file data/tpm.mac");
            goto clean;
        }

        #ifdef PERFORMANCE
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_all);
        // end_all_cpu = clock() / CLOCKS_PER_SEC;
        size_t bufferSize = BUFFERSIZE;

        snprintf(iapString + strlen(iapString), bufferSize, "%f,",
            ((end_send.tv_sec - start_send.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_send.tv_nsec - start_send.tv_nsec) /  (double) NANOSECOND_DIVISOR));
        
        snprintf(iapString + strlen(iapString), bufferSize, "%f,",
            ((end_all.tv_sec - start_all.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_all.tv_nsec - start_all.tv_nsec) /  (double) NANOSECOND_DIVISOR));

        snprintf(iapString + strlen(iapString), bufferSize, "%f,",
            ((end_policy_auth.tv_sec - start_policy_auth.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_policy_auth.tv_nsec - start_policy_auth.tv_nsec) /  (double) NANOSECOND_DIVISOR));

        snprintf(iapString + strlen(iapString), bufferSize, "%f,",
            ((end_derivation.tv_sec - start_derivation.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_derivation.tv_nsec - start_derivation.tv_nsec) /  (double) NANOSECOND_DIVISOR));

        snprintf(iapString + strlen(iapString), bufferSize, "%f\n",
            ((end_hmac.tv_sec - start_hmac.tv_sec) * SECOND_MULTIPLIER + 
            (double) (end_hmac.tv_nsec - start_hmac.tv_nsec) /  (double) NANOSECOND_DIVISOR));

        rc = append_to_file(iapString, strlen(iapString), "iap.perf");
        if(rc!=0){
            LOG_ERROR("Error: %s\n", "append_to_file iapString");
            goto clean;
        }

        #endif


    }

clean:

    free(rawKey);
    free(pemKey);
    free(templateHash);
    free(sessionHash);
    free(nonceTPM);

#ifdef PERFORMANCE
    free(rkpString);
    free(iapString);
#endif

    cleanup(&ctx, *session);
    cleanup(&ctx, *derived_key_handle);
    cleanup(&ctx, key_handle);
    cleanup(&ctx, *session_handle);
    cleanup(&ctx, loaded_key_handle);
    cleanup(&ctx, *challenge_key_handle1);

    Tss2_TctiLdr_Finalize(&tcti_ctx);
    Esys_Finalize(&ctx);

    return rc;
}

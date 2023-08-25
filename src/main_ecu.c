/* Working Mbed-TLS Version: git checkout 3e4d190b4a7dec4738389829b28200bc5fd32dd6*/

#include <argp.h>
#include <stdlib.h>
#include <string.h>

#include "fileHandler.h"
#include "updateHandlerSw.h"

// #include "psa/crypto.h"
#include "mbedtls/sha256.h" /* SHA-256 only */
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define LOGMODULE update
#include "util/log.h"

#define MAXREADSIZE 10000
#define SHA256_DIGEST_LENGTH 32

void print_usage() {
    printf(\
    "Standalone Example:\n"
    "  ./main_ecu --provision --key data/raw.key\n"\
    "  ./main_ecu --verify-hmac --update-data data/update.bin --hmac data/update.mac\n"\
    "  ./main_ecu --answer-challenge --kdf-input data/ecu.ids --challenge data/tpm.nonce1\n"\
    "  ./main_ecu --generate-challenge --out data/ecu.nonce\n"\
    "\n"
    "Full Working Example:\n"
    "   1. PROVISIONING\n"\
    "       ./main_ecu --provision --key data/raw.key\n"\
    "       ./main_tpm --provision --raw-derivation-key data/raw.key --pem-key keys/backend_pub.pem --session-hash data/session.hash\n"\
    "   2. POLICY_CREATION\n"\
    "       ./main_tpm --createpolicies --session-hash data/session.hash --template-hash data/template.hash --secret keys/secret.key\n"\
    "        "
    "   3. AUTHORIZE UPDATE\n"\
    "       ./main_tpm --authorizeinstallation --template-hash data/template.hash --ecu-ids data/ecu.ids"\
    "       ./main_ecu --generate-challenge --out data/challenge.file\n"\
    "       ./main_tpm --authorize-update --update-data data/fw --signature data/signature_kdp.file --digest data/digest.file --pem-key keys/backend_pub.pem --nonce data/challenge.file --template-hash data/template_hash.file --out data/response.file\n"\
    "       ./main_ecu --authorize-update --update-data data/fw --response data/response.file\n"\
    );
}


char *KEYSTORE_PATH_INTERNAL = "ecu_keystore/raw-derivation.key_internal";
char *NONCE_PATH_INTERNAL = "ecu_keystore/nonce.file_internal";

static struct option long_options[] = {
    {"authorize-installation",  no_argument,        0,  'a'},
    {"verify-hmac",             no_argument,        0,  'v'},
    {"challenge",               required_argument,  0,  'c'},
    {"generate-challenge",      no_argument,        0,  'g'},
    {"kdf-input",               required_argument,  0,  'i' },
    {"answer-challenge",        no_argument,        0,  'b'},
    {"key",                     required_argument,  0,  'k' },
    {"out",                     required_argument,  0,  'o' },
    {"provision",               no_argument,        0,  'p' },
    {"tpm-hmac",                required_argument,  0,  't' },
    {"hmac",                    required_argument,  0,  'h' },
    {"update-data",             required_argument,  0,  'u' },
    {0,                         0,                  0,   0  }
};


struct arguments {
    enum { CHARACTER_MODE, WORD_MODE, LINE_MODE } mode;
    enum { NONE, PROVISION, VERIFY_HMAC, ANSWER_CHALLENGE, GENERATE_CHALLENGE, 
        AUTHORIZE_INSTALLATION } command;
    char* filePath;
    char* filePathResponse;
    char* filePathChallenge;
    char* filePathOut;
    char* filePathTPM;
    int mutexCmdCtr;
};

int parse_opt(int argc, char *argv[], struct arguments *arguments){
    int rc = 0;
    int long_index =0;
    int opt= 0;

    arguments->filePathChallenge = "";
    arguments->filePath = "";
    arguments->filePathOut = "";

    while ((opt = getopt_long(argc, argv,"agpr:o:k:h:",
                   long_options, &long_index )) != -1) {
        switch (opt) {
            case 'a': 
                arguments->command = AUTHORIZE_INSTALLATION; 
                arguments->mutexCmdCtr += 1;
                break;
            case 'v': 
                arguments->command = VERIFY_HMAC; 
                arguments->mutexCmdCtr += 1;
                break;
            case 'b':  
                arguments->command = ANSWER_CHALLENGE; 
                arguments->mutexCmdCtr += 1;
                break;
            case 'c': 
                arguments->filePathChallenge = optarg;
                break;
            case 'g': 
                arguments->command = GENERATE_CHALLENGE; 
                arguments->mutexCmdCtr += 1;
                break;
            case 'h': 
                arguments->filePathChallenge = optarg;
                break;
            case 'i': 
                arguments->filePath = optarg;
                break;
            case 'o':
                arguments->filePathOut = optarg;
                break;
            case 'p': 
                arguments->command = PROVISION; 
                arguments->mutexCmdCtr += 1;
                break;
            case 't':
                arguments->filePathTPM = optarg;
                break;
            case 'u':  
                arguments->filePath = optarg;
                break;
            case 'k':  
                arguments->filePath = optarg;
                break;
            default: 
                print_usage();
                return 1;
        }
    }
    return 0;
}


int main(int argc, char *argv[])
{
    struct arguments arguments;
    uint8_t *rawKey = NULL;
    uint8_t *output = NULL;
    uint8_t *updateBundle = NULL;
    uint8_t *kdfinput = NULL;
    uint8_t *hmac = NULL;
    uint8_t *challenge = NULL;
    uint8_t *nonce = NULL;
    uint8_t *nonceTPM = NULL;

    arguments.mutexCmdCtr = 0;
    int rc;

    rc = parse_opt(argc, argv, &arguments);
    if(rc!=0){
        printf("Error: %s\n", "parse_opt");
        goto clean;
    }

    if(arguments.mutexCmdCtr > 1){
        printf("The Commands are mutual exclusive.\n");
        rc = 1;
        goto clean;
    }

    if(arguments.command == PROVISION){
        LOG_TRACE("PROVISION");
        int rawKeySize = 0;
        rawKey = malloc(MAXREADSIZE);

        rc = read_from_file(rawKey, MAXREADSIZE, &rawKeySize, arguments.filePath);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file rawKey");
            goto clean;
        }

        // LOGBLOB_ERROR(rawKey, rawKeySize, "rawKey");

        rc = write_to_file(rawKey, rawKeySize, KEYSTORE_PATH_INTERNAL);
        if(rc!=0){
            printf("Error: %s\n", "write_to_file rawKey");
            goto clean;
        }
    }

    if(arguments.command == VERIFY_HMAC){
        LOG_TRACE("VERIFY_HMAC");

        if (strlen(arguments.filePath) == 0){
            LOG_ERROR("%s\n", "Update data is missing. Please specify with 'update-data' or 'u'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePathChallenge) == 0){
            LOG_ERROR("%s\n", "HMAC is missing. Please specify with 'hmac' or 'h'");
            rc = 1;
            goto clean;
        }

        /* Read update bundle */
        int updateBundleSize, rawKeySize, hmacSize, nonceSize;
        updateBundle = malloc(MAXREADSIZE);
        rawKey = malloc(MAXREADSIZE);
        hmac = malloc(MAXREADSIZE);

        rc = read_from_file(rawKey, MAXREADSIZE, &rawKeySize, KEYSTORE_PATH_INTERNAL);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file rawKey");
            goto clean;
        }

        LOGBLOB_TRACE(rawKey, rawKeySize, "rawKey");

        rc = read_from_file(updateBundle, MAXREADSIZE, &updateBundleSize, arguments.filePath);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file updateBundle");
            goto clean;
        }

        LOGBLOB_TRACE(updateBundle, updateBundleSize, "updateBundle");

        rc = read_from_file(hmac, MAXREADSIZE, &hmacSize, arguments.filePathChallenge);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file hmac");
            goto clean;
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        mbedtls_sha256_context sha256_ctx;
     
        mbedtls_sha256_init(&sha256_ctx);
        rc = mbedtls_sha256_starts_ret(&sha256_ctx, 0); /* SHA-256, not 224 */
        if(rc!=0){
            printf("Error: %s\n", "mbedtls_sha256_starts_ret");
            goto clean;
        }

        rc = mbedtls_sha256_update_ret(&sha256_ctx, updateBundle, updateBundleSize);
        if(rc!=0){
            printf("Error: %s\n", "mbedtls_sha256_update_ret");
            goto clean;
        }

        rc = mbedtls_sha256_finish_ret(&sha256_ctx, hash);
        if(rc!=0){
            printf("Error: %s\n", "mbedtls_sha256_finish_ret");
            goto clean;
        }

        LOGBLOB_TRACE(hash, SHA256_DIGEST_LENGTH, "Hash");

        uint32_t expectedKeySize = TPM2_SHA256_DIGEST_SIZE;
        uint8_t *derivedKey;
        derivedKey = malloc(expectedKeySize);

        rc = deriveUpdateKey(ALG_SHA256, rawKey, rawKeySize, hash, SHA256_DIGEST_LENGTH, 
            NULL, 0, KDF_LIMIT, expectedKeySize, derivedKey);
        if(rc != 0){
            LOG_ERROR("deriveUpdateKey");
            goto clean;
        }

        LOGBLOB_TRACE(derivedKey, expectedKeySize, "derivedKey");

        size_t outputMacSize = SHA256_DIGEST_SIZE;
        uint8_t *outputMac;
        outputMac = malloc(outputMacSize);

        rc = createHMAC(ALG_SHA256, derivedKey, expectedKeySize, hash, 
            SHA256_DIGEST_LENGTH, outputMac, &outputMacSize);
        if(rc!=0){
            LOG_ERROR("createHMACTPM");
            goto clean;
        }

        LOGBLOB_TRACE(outputMac, outputMacSize, "outputMac");
        LOGBLOB_TRACE(hmac, hmacSize, "hmac");

        rc = memcmp(outputMac, hmac, outputMacSize);
        if(rc != 0){
            LOG_ERROR("MAC comparison failed");
            goto clean;
        }
        else{
            printf("REKEYING SUCCESS\n");
        }
    }

    if(arguments.command == ANSWER_CHALLENGE){
        LOG_TRACE("ANSWER_CHALLENGE");

        if (strlen(arguments.filePathOut) == 0){
            LOG_ERROR("%s\n", "File Path for out hmac is missing. Please specify with 'out' or 'o'");
            rc = 1;
            goto clean;
        }

        /* Read update bundle */
        int kdfinputSize, rawKeySize, nonceTPMSize, nonceSize;
        kdfinput = malloc(MAXREADSIZE);
        rawKey = malloc(MAXREADSIZE);
        nonceTPM = malloc(MAXREADSIZE);
        // nonce = malloc(MAXREADSIZE);

        rc = read_from_file(rawKey, MAXREADSIZE, &rawKeySize, KEYSTORE_PATH_INTERNAL);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file rawKey");
            goto clean;
        }

        rc = read_from_file(kdfinput, MAXREADSIZE, &kdfinputSize, arguments.filePath);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file kdfinput");
            goto clean;
        }

        rc = read_from_file(nonceTPM, MAXREADSIZE, &nonceTPMSize, arguments.filePathChallenge);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file nonceTPM");
            goto clean;
        }

        LOGBLOB_TRACE(nonceTPM, nonceTPMSize, "nonceTPM");

        uint32_t expectedKeySize = TPM2_SHA256_DIGEST_SIZE;
        uint8_t *derivedKey;
        derivedKey = malloc(expectedKeySize);

        LOGBLOB_TRACE(rawKey, rawKeySize, "rawKey");
        LOGBLOB_TRACE(kdfinput, kdfinputSize, "kdfinput");

        kdfinputSize=1;
        LOGBLOB_TRACE(kdfinput, kdfinputSize, "kdfinput");
        rc = deriveUpdateKey(ALG_SHA256, rawKey, rawKeySize, &kdfinput[0],
            kdfinputSize, NULL, 0, KDF_LIMIT, expectedKeySize, derivedKey);
        if(rc != 0){
            LOG_ERROR("deriveUpdateKey");
            goto clean;
        }

        LOGBLOB_TRACE(derivedKey, expectedKeySize, "derivedKey");

        size_t outputMacSize = SHA256_DIGEST_SIZE;
        uint8_t *outputMac;
        outputMac = malloc(outputMacSize);

        uint32_t expiration = { 0x0 };
        // int expirationSize = 1;
        // expiration = malloc(expirationSize);

        rc = createHMACPolicySigned(ALG_SHA256, derivedKey, expectedKeySize, 
            nonceTPM, nonceTPMSize, expiration, NULL /* cpHashA */, 
            0, NULL /* policyRef */, 0, outputMac, &outputMacSize);
        if(rc!=0){
            printf("Error: %s\n", "createHMACPolicySigned");
            goto clean;
        }

        // rc = createHMAC(ALG_SHA256, derivedKey, expectedKeySize, challenge, 
        //     challengeSize, outputMac, &outputMacSize); 
        // if(rc!=0){
        //     printf("Error: %s\n", "createHMAC");
        //     goto clean;
        // }

        rc = write_to_file(outputMac, outputMacSize, arguments.filePathOut);
        if(rc!=0){
            LOG_ERROR("write_to_file %s", arguments.filePathOut);
            goto clean;
        }

        LOGBLOB_TRACE(outputMac, outputMacSize, "outputMac");

        // printf("Success. MAC written to `%s`.\n", "data/ecu.response1");
    }

    if(arguments.command == GENERATE_CHALLENGE){

        if (strlen(arguments.filePathOut) == 0){
            LOG_ERROR("%s\n", "File Path for out nonce is missing. Please specify with 'out' or 'o'");
            rc = 1;
            goto clean;
        }

        LOG_TRACE("GENERATE_CHALLENGE");
        size_t outputSize = 32;
        output = malloc(outputSize);

        char *personalization = "my_app_specific_string";
        mbedtls_entropy_context entropy;
        mbedtls_entropy_init( &entropy );

        mbedtls_ctr_drbg_context ctr_drbg;

        mbedtls_ctr_drbg_init (&ctr_drbg);
        rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
            (const unsigned char *) personalization, strlen( personalization ) );
        if(rc!=0){
            printf("Error: %s\n", "mbedtls_ctr_drbg_seed");
            goto clean;
        }

        rc = mbedtls_ctr_drbg_random(&ctr_drbg, output, outputSize);
        if(rc!=0){
            printf("Error: %s\n", "mbedtls_ctr_drbg_random");
            goto clean;
        }

        LOG_DEBUG("outputSize %ld\n", outputSize);
        LOGBLOB_DEBUG(output, outputSize, "output");
        LOG_DEBUG("filePathOut: %s", arguments.filePathOut);

        rc = write_to_file(output, outputSize, arguments.filePathOut);
        if(rc!=0){
            LOG_ERROR("%s", "write_to_file arguments.filePathOut");
            goto clean;
        }

        rc = write_to_file(output, outputSize, NONCE_PATH_INTERNAL);
        if(rc!=0){
            LOG_ERROR("%s", "write_to_file NONCE_PATH_INTERNAL");
            goto clean;
        }   
    }

    if(arguments.command == AUTHORIZE_INSTALLATION){

        if (strlen(arguments.filePathTPM) == 0){
            LOG_ERROR("%s\n", "TPM hmac path is missing. Please specify with 'tpm-hmac' or 'z'");
            rc = 1;
            goto clean;
        }

        if (strlen(arguments.filePath) == 0){
            LOG_ERROR("%s\n", "Update data is missing. Please specify with 'update-data' or 'u'");
            rc = 1;
            goto clean;
        }

        int nonceSize, rawKeySize, hmacSize, updateBundleSize, update;
        nonce = malloc(MAXREADSIZE);
        hmac = malloc(MAXREADSIZE);
        rawKey = malloc(MAXREADSIZE);
        updateBundle = malloc(MAXREADSIZE);

        rc = read_from_file(nonce, MAXREADSIZE, &nonceSize, NONCE_PATH_INTERNAL);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file NONCE_PATH_INTERNAL");
            goto clean;
        }

        rc = read_from_file(rawKey, MAXREADSIZE, &rawKeySize, KEYSTORE_PATH_INTERNAL);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file rawKey");
            goto clean;
        }

        rc = read_from_file(hmac, MAXREADSIZE, &hmacSize, arguments.filePathTPM);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file hmac");
            goto clean;
        }

        rc = read_from_file(updateBundle, MAXREADSIZE, &updateBundleSize, arguments.filePath);
        if(rc!=0){
            printf("Error: %s\n", "read_from_file updateBundle");
            goto clean;
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        mbedtls_sha256_context sha256_ctx;
     
        mbedtls_sha256_init(&sha256_ctx);
        rc = mbedtls_sha256_starts_ret(&sha256_ctx, 0); /* SHA-256, not 224 */
        if(rc!=0){
            printf("Error: %s\n", "mbedtls_sha256_starts_ret");
            goto clean;
        }

        rc = mbedtls_sha256_update_ret(&sha256_ctx, updateBundle, updateBundleSize);
        if(rc!=0){
            printf("Error: %s\n", "mbedtls_sha256_update_ret");
            goto clean;
        }

        rc = mbedtls_sha256_finish_ret(&sha256_ctx, hash);
        if(rc!=0){
            printf("Error: %s\n", "mbedtls_sha256_finish_ret");
            goto clean;
        }

        LOGBLOB_TRACE(hash, SHA256_DIGEST_LENGTH, "Hash");

        uint32_t expectedKeySize = TPM2_SHA256_DIGEST_SIZE;
        uint8_t *derivedKey;
        derivedKey = malloc(expectedKeySize);


        rc = deriveUpdateKey(ALG_SHA256, rawKey, rawKeySize, hash,
            SHA256_DIGEST_LENGTH, NULL, 0, KDF_LIMIT, expectedKeySize, derivedKey);
        if(rc != 0){
            LOG_ERROR("deriveUpdateKey");
            goto clean;
        }

        LOGBLOB_TRACE(derivedKey, expectedKeySize, "derivedKey");

        size_t outputMacSize = SHA256_DIGEST_SIZE;
        uint8_t *outputMac;
        outputMac = malloc(outputMacSize);

        rc = createHMAC(ALG_SHA256, derivedKey, expectedKeySize, nonce, 
            nonceSize, outputMac, &outputMacSize);
        if(rc!=0){
            LOG_ERROR("createHMAC");
            goto clean;
        }

        LOGBLOB_TRACE(outputMac, outputMacSize, "outputMac");
        LOGBLOB_TRACE(hmac, hmacSize, "hmac");

        rc = memcmp(outputMac, hmac, outputMacSize);
        if(rc != 0){
            LOG_ERROR("MAC comparison failed");
            goto clean;
        }
        else{
            printf("INSTALLATION SUCCESS\n");
        }


    }

clean:
    if (rawKey)
        free(rawKey);
    if (output)
        free(output);
    if (updateBundle)
        free(updateBundle);
    if (hmac)
        free(hmac);
    if (nonce)
        free(nonce);

    return rc;
}
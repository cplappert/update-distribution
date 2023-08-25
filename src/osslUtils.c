#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>

#include "tss2_tpm2_types.h"

#include "osslUtils.h"

#define LOGMODULE update
#include "util/log.h"

int rc = 1;

static const struct {
    TPMI_ECC_CURVE curve;
    int nid;
} nid_curve_map[] = {
    { TPM2_ECC_NIST_P192, NID_X9_62_prime192v1 },
    { TPM2_ECC_NIST_P224, NID_secp224r1        },
    { TPM2_ECC_NIST_P256, NID_X9_62_prime256v1 },
    { TPM2_ECC_NIST_P384, NID_secp384r1        },
    { TPM2_ECC_NIST_P521, NID_secp521r1        }
    /*
     * XXX
     * See if it's possible to support the other curves, I didn't see the
     * mapping in OSSL:
     *  - TPM2_ECC_BN_P256
     *  - TPM2_ECC_BN_P638
     *  - TPM2_ECC_SM2_P256
     */
};


/**
 * Maps an OSSL nid as defined obj_mac.h to a TPM2 ECC curve id.
 * @param nid
 *  The nid to map.
 * @return
 *  A valid TPM2_ECC_* or TPM2_ALG_ERROR on error.
 */
static TPMI_ECC_CURVE ossl_nid_to_curve(int nid) {

    unsigned i;
    for (i = 0; i < ARRAY_LEN(nid_curve_map); i++) {
        TPMI_ECC_CURVE c = nid_curve_map[i].curve;
        int n = nid_curve_map[i].nid;

        if (n == nid) {
            return c;
        }
    }

    LOG_ERROR("Cannot map nid \"%d\" to TPM ECC curve", nid);
    return TPM2_ALG_ERROR;
}

static int load_public_RSA_from_key(RSA *k, TPM2B_PUBLIC *pub) {

    TPMT_PUBLIC *pt = &pub->publicArea;
    pt->type = TPM2_ALG_RSA;

    TPMS_RSA_PARMS *rdetail = &pub->publicArea.parameters.rsaDetail;
    rdetail->scheme.scheme = TPM2_ALG_NULL;
    rdetail->symmetric.algorithm = TPM2_ALG_NULL;
    rdetail->scheme.details.anySig.hashAlg = TPM2_ALG_NULL;

    /* NULL out sym details */
    TPMT_SYM_DEF_OBJECT *sym = &rdetail->symmetric;
    sym->algorithm = TPM2_ALG_NULL;
    sym->keyBits.sym = 0;
    sym->mode.sym = TPM2_ALG_NULL;

    const BIGNUM *n; /* modulus */
    const BIGNUM *e; /* public key exponent */

#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    n = k->n;
    e = k->e;
#else
    RSA_get0_key(k, &n, &e, NULL);
#endif

    /*
     * The size of the modulus is the key size in RSA, store this as the
     * keyBits in the RSA details.
     */
    rdetail->keyBits = BN_num_bytes(n) * 8;
    switch (rdetail->keyBits) {
    case 1024: /* falls-through */
    case 2048: /* falls-through */
    case 4096: /* falls-through */
        break;
    default:
        LOG_ERROR("RSA key-size %u is not supported", rdetail->keyBits);
        return false;
    }

    /* copy the modulus to the unique RSA field */
    pt->unique.rsa.size = rdetail->keyBits / 8;
    int success = BN_bn2bin(n, pt->unique.rsa.buffer);
    if (!success) {
        LOG_ERROR("Could not copy public modulus N");
        return false;
    }

    /*Make sure that we can fit the exponent into a UINT32 */
    unsigned e_size = BN_num_bytes(e);
    if (e_size > sizeof(rdetail->exponent)) {
        LOG_ERROR(
                "Exponent is too big. Got %d expected less than or equal to %zu",
                e_size, sizeof(rdetail->exponent));
        return false;
    }

    /*
     * Copy the exponent into the field.
     * Returns 1 on success false on error.
     */
    BN_bn2bin(e, (unsigned char *) &rdetail->exponent);

    return 0;
}

static int load_public_ECC_from_key(EC_KEY *k, TPM2B_PUBLIC *pub) {

    int result = 1;

    BIGNUM *y = BN_new();
    BIGNUM *x = BN_new();
    if (!x || !y) {
        LOG_ERROR("oom");
        goto out;
    }

    /*
     * Set the algorithm type
     */
    pub->publicArea.type = TPM2_ALG_ECC;

    /*
     * Get the curve type
     */
    const EC_GROUP *group = EC_KEY_get0_group(k);
    int nid = EC_GROUP_get_curve_name(group);

    TPMS_ECC_PARMS *pp = &pub->publicArea.parameters.eccDetail;
    TPM2_ECC_CURVE curve_id = ossl_nid_to_curve(nid); // Not sure what lines up with NIST 256...
    if (curve_id == TPM2_ALG_ERROR) {
        goto out;
    }

    pp->curveID = curve_id;

    /*
     * Set the unique data to the public key.
     */
    const EC_POINT *point = EC_KEY_get0_public_key(k);

    int ret = EC_POINT_get_affine_coordinates_tss(group, point, x, y, NULL);
    if (!ret) {
        LOG_ERROR("Could not get X and Y affine coordinates");
        goto out;
    }

    /*
     * Copy the X and Y coordinate data into the ECC unique field,
     * ensuring that it fits along the way.
     */
    TPM2B_ECC_PARAMETER *X = &pub->publicArea.unique.ecc.x;
    TPM2B_ECC_PARAMETER *Y = &pub->publicArea.unique.ecc.y;

    unsigned x_size = (EC_GROUP_get_degree(group) + 7) / 8;
    if (x_size > sizeof(X->buffer)) {
        LOG_ERROR("X coordinate is too big. Got %u expected less than or equal to"
                " %zu", x_size, sizeof(X->buffer));
        goto out;
    }

    unsigned y_size = (EC_GROUP_get_degree(group) + 7) / 8;
    if (y_size > sizeof(Y->buffer)) {
        LOG_ERROR("X coordinate is too big. Got %u expected less than or equal to"
                " %zu", y_size, sizeof(Y->buffer));
        goto out;
    }

    X->size = BN_bn2binpad(x, X->buffer, x_size);
    if (X->size != x_size) {
        LOG_ERROR("Error converting X point BN to binary");
        goto out;
    }

    Y->size = BN_bn2binpad(y, Y->buffer, y_size);
    if (Y->size != y_size) {
        LOG_ERROR("Error converting Y point BN to binary");
        goto out;
    }

    /*
     * no kdf - not sure what this should be
     */
    pp->kdf.scheme = TPM2_ALG_NULL;
    pp->scheme.scheme = TPM2_ALG_NULL;
    pp->symmetric.algorithm = TPM2_ALG_NULL;
    pp->scheme.details.anySig.hashAlg = TPM2_ALG_NULL;

    /* NULL out sym details */
    TPMT_SYM_DEF_OBJECT *sym = &pp->symmetric;
    sym->algorithm = TPM2_ALG_NULL;
    sym->keyBits.sym = 0;
    sym->mode.sym = TPM2_ALG_NULL;

    result = 0;

out:
    if (x) {
        BN_free(x);
    }
    if (y) {
        BN_free(y);
    }

    return result;
}

static int load_public_ECC_from_pem(FILE *f, const char *path, TPM2B_PUBLIC *pub) {
    EC_KEY *k = tpm2_openssl_get_public_ECC_from_pem(f, path);
    if (!k) {
        // ERR_print_errors_fp(stderr);
        LOG_ERROR("tpm2_openssl_get_public_ECC_from_pem: %s", path);
        return false;
    }

    rc = load_public_ECC_from_key(k, pub);
    if (rc != 0) {
        // ERR_print_errors_fp(stderr);
        LOG_ERROR("load_public_ECC_from_key");
    }

    EC_KEY_free(k);

    return rc;
}

static int load_public_RSA_from_pem(FILE *f, const char *path,
        TPM2B_PUBLIC *pub) {

    /*
     * Public PEM files appear in two formats:
     * 1. PEM format, read with PEM_read_RSA_PUBKEY
     * 2. PKCS#1 format, read with PEM_read_RSAPublicKey
     *
     * See:
     *  - https://stackoverflow.com/questions/7818117/why-i-cant-read-openssl-generated-rsa-pub-key-with-pem-read-rsapublickey
     */
    RSA *k = tpm2_openssl_get_public_RSA_from_pem(f, path);
    if (!k) {
        /* tpm2_openssl_get_public_RSA_from_pem() should already log errors */
        LOG_ERROR("tpm2_openssl_get_public_RSA_from_pem");
        return 1;
    }

    rc = load_public_RSA_from_key(k, pub);
    if (rc != 0) {
        // ERR_print_errors_fp(stderr);
        LOG_ERROR("load_public_RSA_from_key");
    }

    RSA_free(k);

    return rc;
}

RSA *tpm2_openssl_get_public_RSA_from_pem(FILE *f, const char *path) {

    /*
     * Public PEM files appear in two formats:
     * 1. PEM format, read with PEM_read_RSA_PUBKEY
     * 2. PKCS#1 format, read with PEM_read_RSAPublicKey
     *
     * See:
     *  - https://stackoverflow.com/questions/7818117/why-i-cant-read-openssl-generated-rsa-pub-key-with-pem-read-rsapublickey
     */
    RSA *pub = PEM_read_RSA_PUBKEY(f, NULL, NULL, NULL);
    if (!pub) {
        pub = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
    }

    if (!pub) {
        // ERR_print_errors_fp(stderr);
        LOG_ERROR("Reading public PEM file \"%s\" failed", path);
        return NULL;
    }

    return pub;
}


EC_KEY *tpm2_openssl_get_public_ECC_from_pem(FILE *f, const char *path) {

    EC_KEY *pub = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL);
    if (!pub) {
        // ERR_print_errors_fp(stderr);
        LOG_ERROR("Reading public PEM file \"%s\" failed", path);
        return NULL;
    }

    return pub;
}

int tpm2_openssl_load_public(const char *path, TPMI_ALG_PUBLIC alg,
    TPM2B_PUBLIC *pub){
    int result = 1;

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERROR("Could not open file \"%s\"", path);
        return result;
    }

    switch (alg) {
    case TPM2_ALG_RSA:
        result = load_public_RSA_from_pem(f, path, pub);
         if(result != 0){
            LOG_ERROR("load_public_RSA_from_pem");
        }
        else{
            result = 0;
        }
        break;
    case TPM2_ALG_ECC:
        result = load_public_ECC_from_pem(f, path, pub);
        if(result != 0){
            LOG_ERROR("load_public_ECC_from_pem");
        }
        else{
            result = 0;
        }
        break;
        /* Skip AES here, as we can only load this one from a private file */
    default:
        /* default try TSS */
        LOG_ERROR("Default not implemented yet");
        // result = files_load_public(path, pub);
    }

    fclose(f);

    return result;
}


int asciiToHex(uint8_t *buffer, size_t buffer_size, uint8_t *hex_buffer, 
    size_t *hex_buffer_size){

    *hex_buffer_size = buffer_size*2;
    uint8_t hexstr[*hex_buffer_size*2];
    const char HEX[16] = "0123456789abcdef";

    for(size_t i=0, j=0; i < *hex_buffer_size; i++, j=j+2){
        hexstr[j] =  HEX[(buffer[i] & 0xF0) >> 4];
        hexstr[j+1] =  HEX[(buffer[i] & 0x0F)];
    }
    
    memcpy(hex_buffer, hexstr, *hex_buffer_size);

    return 0;
}
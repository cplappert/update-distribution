#include <openssl/pem.h>

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#define EC_POINT_set_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_set_affine_coordinates(group, tpm_pub_key, bn_x, bn_y, dmy)

#define EC_POINT_get_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_get_affine_coordinates(group, tpm_pub_key, bn_x, bn_y, dmy)

RSA *tpm2_openssl_get_public_RSA_from_pem(FILE *f, const char *path);
EC_KEY *tpm2_openssl_get_public_ECC_from_pem(FILE *f, const char *path);

/**
 * Loads a public portion of a key from a file. Files can be the raw key, in the case
 * of symmetric ciphers, or a PEM file.
 *
 * @param path
 *  The path to load from.
 * @param alg
 *  algorithm type to import.
 * @param pub
 *  The public structure to populate.
 * @return
 *  True on success, false on failure.
 */
int tpm2_openssl_load_public(const char *path, TPMI_ALG_PUBLIC alg,
    TPM2B_PUBLIC *pub);


int getRandSfromDerSignature(uint8_t *der_signature, size_t der_signature_size, 
    unsigned char *signature_r, short unsigned int *signature_r_size, unsigned char *signature_s,
    short unsigned int *signature_s_size);

int asciiToHex(uint8_t *buffer, size_t buffer_size, uint8_t *hex_buffer, 
    size_t *hex_buffer_size);
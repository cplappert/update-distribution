#ifndef _TPM2_TEMPLATES_H 
#define _TPM2_TEMPLATES_H

/* Used as template to load external PEM key into TPM */
TPM2B_PUBLIC keyEcTemplate = {
    .publicArea /* TPMT_PUBLIC */ = {
        .type /* TPMI_ALG_PUBLIC */ = TPM2_ALG_ECC, /* 0x0023 */
        .nameAlg /* TPMI_ALG_HASH */ = TPM2_ALG_SHA256, /* 0x000B */
        .objectAttributes /* TPMA_OBJECT */ = (
            TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_SIGN_ENCRYPT |
            TPMA_OBJECT_DECRYPT),
            // TPMA_OBJECT_FIXEDTPM |
            // TPMA_OBJECT_FIXEDPARENT |
            // TPMA_OBJECT_SENSITIVEDATAORIGIN |
            // TPMA_OBJECT_NODA),
        .parameters.eccDetail /* TPMU_PUBLIC_PARMS . TPMS_ECC_PARMS */ = {
             .curveID /* TPMI_ECC_CURVE */ = TPM2_ECC_NIST_P256, /* 0x0003 */
             .symmetric /* TPMT_SYM_DEF_OBJECT */ = {
                .algorithm /* TPMI_ALG_SYM_OBJECT */= TPM2_ALG_NULL, /* 0x0010 */
                .keyBits.aes /* TPMU_SYM_KEY_BITS */ = 0, /* 0x0 */
                .mode.aes /* TPMU_SYM_MODE . TPMI_ALG_SYM_MODE */ = 0, /* 0x0 */
              },
            .scheme /* TPMT_ECC_SCHEME */ = {
                .scheme /* TPMI_ALG_ECC_SCHEME */ = TPM2_ALG_ECDSA, /* ? */
                .details /* TPMU_ASYM_SCHEME */ = {
                    .ecdsa /* TPMS_SIG_SCHEME_ECDSA */ = TPM2_ALG_SHA256
                }
            },
            .kdf /* TPMT_KDF_SCHEME */ = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
            },
        },
        .unique.ecc /* TPMU_PUBLIC_ID . TPMS_ECC_POINT */= {
            .x.size = 0,
            .y.size = 0
        }
    }
};

/* Used as template to create id key */
TPM2B_PUBLIC inPublicIdKeyTemplate = {
    .publicArea /* TPMT_PUBLIC */ = {
        .type /* TPMI_ALG_PUBLIC */ = TPM2_ALG_ECC, /* 0x0023 */
        .nameAlg /* TPMI_ALG_HASH */ = TPM2_ALG_SHA256, /* 0x000B */
        .objectAttributes /* TPMA_OBJECT */ = (
            TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_SIGN_ENCRYPT |
            // TPMA_OBJECT_DECRYPT),
            TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN |
            TPMA_OBJECT_NODA
        ),
        .parameters.eccDetail /* TPMU_PUBLIC_PARMS . TPMS_ECC_PARMS */ = {
             .curveID /* TPMI_ECC_CURVE */ = TPM2_ECC_NIST_P256, /* 0x0003 */
             .symmetric /* TPMT_SYM_DEF_OBJECT */ = {
                .algorithm /* TPMI_ALG_SYM_OBJECT */= TPM2_ALG_NULL, /* 0x0010 */
                .keyBits.aes /* TPMU_SYM_KEY_BITS */ = 0, /* 0x0 */
                .mode.aes /* TPMU_SYM_MODE . TPMI_ALG_SYM_MODE */ = 0, /* 0x0 */
              },
            .scheme /* TPMT_ECC_SCHEME */ = {
                .scheme /* TPMI_ALG_ECC_SCHEME */ = TPM2_ALG_ECDSA, /* ? */
                .details /* TPMU_ASYM_SCHEME */ = {
                    .ecdsa /* TPMS_SIG_SCHEME_ECDSA */ = TPM2_ALG_SHA256
                }
            },
            .kdf /* TPMT_KDF_SCHEME */ = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
            },
        },
        .unique.ecc /* TPMU_PUBLIC_ID . TPMS_ECC_POINT */= {
            .x.size = 0,
            .y.size = 0
        }
    }
};

/* Used as template for the key derivation parent  */
TPM2B_PUBLIC inPublicDerivationParentTemplate = {
    .size = 0,
    .publicArea /* TPMT_PUBLIC */ = {
        .type = TPM2_ALG_KEYEDHASH,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (
            // TPMA_OBJECT_USERWITHAUTH | // SET 1 Approval of USER role actions with this object may be with an HMAC session or with a password using the authValue of the object or a policy session. CLEAR 0 Approval of USER role actions with this object may only be done with a policy session. 
            TPMA_OBJECT_DECRYPT |       // 0x00020000
            TPMA_OBJECT_RESTRICTED |    // 0x00010000
            TPMA_OBJECT_NODA            // 0x00000400
            // TPMA_OBJECT_FIXEDTPM |
            // TPMA_OBJECT_FIXEDPARENT |
            // TPMA_OBJECT_SENSITIVEDATAORIGIN
        ),
        .authPolicy = {
             .size = 0,
         },       
        .parameters/* TPMU_PUBLIC_PARMS */.keyedHashDetail/* TPMS_KEYEDHASH_PARMS */ = {
            .scheme/* TPMT_KEYEDHASH_SCHEME */ = {
                .scheme/* TPMI_ALG_KEYEDHASH_SCHEME */ = TPM2_ALG_XOR,
                .details/* TPMU_SCHEME_KEYEDHASH */ = {
                    .exclusiveOr/* TPMS_SCHEME_XOR */ = {
                        .hashAlg /* TPMI_ALG_HASH */  = TPM2_ALG_SHA256,
                        .kdf/* TPMI_ALG_KDF */ = TPM2_ALG_KDF1_SP800_108
                    },
                },
                // .scheme = TPM2_ALG_HMAC,
                // .details/* TPMU_SCHEME_KEYEDHASH */.hmac/* TPMS_SCHEME_HMAC */.hashAlg/* TPMI_ALG_HASH */ = TPM2_ALG_SHA256
            },
        },
    },
};

/* Used as template for the derived application key */
TPMT_PUBLIC inPublicDerivedApplicationKeyTemplate = {
    .type = TPM2_ALG_KEYEDHASH,
    .nameAlg = TPM2_ALG_SHA256,
    .objectAttributes = (
        TPMA_OBJECT_USERWITHAUTH |
        TPMA_OBJECT_SIGN_ENCRYPT |
        TPMA_OBJECT_FIXEDPARENT
        // TPMA_OBJECT_SENSITIVEDATAORIGIN
        ),
    .authPolicy = { /* TPM2B_DIGEST */
         .size = 0,
    },
    .parameters.keyedHashDetail = {
         .scheme = {
              .scheme = TPM2_ALG_HMAC,
              .details.hmac.hashAlg = TPM2_ALG_SHA256
          },
    },
    .unique/* TPMU_PUBLIC_ID */ = {
        .derive/* TPMS_DERIVE */ = {
            .label/* TPM2B_LABEL */ = {0},
            .context /* TPM2B_LABEL */ = {0}
        }
    }
};

// 0008000b0004005000000005000b0000

// #define TPM2_ALG_KEYEDHASH           ((TPM2_ALG_ID) 0x0008)
// #define TPM2_ALG_SHA256              ((TPM2_ALG_ID) 0x000B)
// #define TPMA_OBJECT_FIXEDPARENT      ((TPMA_OBJECT) 0x00000010) /* SET 1 The parent of the object may not change. CLEAR 0 The parent of the object may change as the result of a TPM2_Duplicate of the object. */
// #define TPMA_OBJECT_USERWITHAUTH     ((TPMA_OBJECT) 0x00000040) /* SET 1 Approval of USER role actions with this object may be with an HMAC session or with a password using the authValue of the object or a policy session. CLEAR 0 Approval of USER role actions with this object may only be done with a policy session. */
// #define TPMA_OBJECT_SIGN_ENCRYPT     ((TPMA_OBJECT) 0x00040000) /* SET 1 For a symmetric cipher object the private portion of the key may be used to encrypt. For other objects the private portion of the key may be used to sign. CLEAR 0 The private portion of the key may not be used to sign or encrypt. */
//                                                     0x00 0x00
// #define TPM2_ALG_HMAC                ((TPM2_ALG_ID) 0x0005)
// #define TPM2_ALG_SHA256              ((TPM2_ALG_ID) 0x000B)
// struct TPM2B_DIGEST {
//     UINT16 size; 2x00
//     BYTE buffer[sizeof(TPMU_HA)]; 32x00
// };

/* Initialize data structure for primary key's insensitive
 * parameters.
 */
TPM2B_SENSITIVE_CREATE inSensitivePrimaryKeyTemplate = {
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



/* Additional information to be included into the key's creation
 * data.
 */
TPM2B_DATA outsideInfoEmpty = {
    .size = 0,
    .buffer = {},
};

/* Selection of PCRs to be included into the key's creation
 * data.
 */
TPML_PCR_SELECTION creationPCREmpty = {
    .count = 0,
};

#endif /* _TPM2_TEMPLATES_H */
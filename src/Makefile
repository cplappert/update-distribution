TSS=./requiredSoftware/tpm2-tss-extended
TSS_SRC=$(TSS)/src
ESAPI_PATH=$(TSS_SRC)/tss2-esys
UTIL_PATH=$(TSS_SRC)/util
TSS_INCLUDE_PATH=$(TSS)/include/tss2
TSS_INCLUDE_PATH_UTIL=$(TSS_SRC)

MBEDTLS=./requiredSoftware/mbedtls
MBEDTLS_LIBRARY=$(MBEDTLS)/library
MBEDTLS_INCLUDE_PATH=$(MBEDTLS)/include
MBEDTLS_CONFIG_PATH=./

CFLAGS=-O0 -g -DMAXLOGLEVEL=6 -I$(TSS_INCLUDE_PATH) -I$(TSS_INCLUDE_PATH_UTIL) \
	-I$(MBEDTLS_INCLUDE_PATH) -I$(MBEDTLS_CONFIG_PATH) \
	-DMBEDTLS_CONFIG_FILE='<mbedtls_config.h>' -DPERFORMANCE

mbed_objects = aes.c aesni.c arc4.c blowfish.c camellia.c ccm.c chacha20.c \
	chachapoly.c cipher_wrap.c cipher.c cmac.c ctr_drbg.c des.c entropy.c \
	entropy_poll.c gcm.c md.c md5.c platform_util.c poly1305.c \
	ripemd160.c sha1.c sha256.c sha512.c timing.c # bignum.c asn1parse.c

PROGRAMS=keyDerivation main_tpm main_ecu fileHandler updateHandler libTPMsHelper

ESYS_OSSL=$(ESAPI_PATH)/esys_crypto_ossl $(ESAPI_PATH)/esys_crypto

all: $(PROGRAMS)

main_tpm: main_tpm.o fileHandler.o updateHandlerTpm.o osslUtils.o $(UTIL_PATH)/log.o
	gcc $(CFLAGS) -o main_tpm main_tpm.o fileHandler.o updateHandlerTpm.o osslUtils.o $(UTIL_PATH)/log.o \
	$(addprefix $(MBEDTLS_LIBRARY)/,$(mbed_objects)) -ltss2-esys -ltss2-tctildr -ltss2-mu -lcrypto

main_ecu: main_ecu.o fileHandler.o updateHandlerSw.o $(UTIL_PATH)/log.o
	gcc $(CFLAGS) -o main_ecu main_ecu.o fileHandler.o updateHandlerSw.o \
	$(UTIL_PATH)/log.o $(addprefix $(MBEDTLS_LIBRARY)/,$(mbed_objects)) \
	-lcrypto

clean:
	rm -f $(PROGRAMS) *.o
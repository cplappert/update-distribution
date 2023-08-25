#!/bin/bash


# 1. bash main_backend.sh createbackendkeys
# 2. bash main_backend.sh createupdate
# 3. bash main_backend.sh createtemplatehash
# 4. bash main_backend.sh createconditionecuids

# 4. create policies with main_tpm
# 5. bash main_backend.sh signpolicies keys/backend_priv.pem data/rkp.digest data/iap.digest

function backend_allcmds {
	ALG="ecc"

	if [ "${2}" = "rsa" ]; then
		ALG="rsa"
	fi

	bash main-backend.sh createbackendkeys keys $ALG
	bash main-backend.sh createupdate data 2kB
	bash main-backend.sh signupdate keys/backend_priv_$ALG.pem data/update.bin
	bash main-backend.sh createderivationsecret
	bash main-backend.sh createsessionhash
	bash main-backend.sh createtemplatehash data/update.bin
	bash main-backend.sh createconditionecuids
	mkdir -p ecu_keystore
}

# Create backend key pair

function backend_createbackendkeys {

	DIRECTORY=keys

	if [ -z ${2} ]; then 
		echo "set to default directory 'keys'";
	else 
		echo "set directory to '$2'";
		DIRECTORY=$2
	fi

	rm -rf $DIRECTORY/*.pem
	mkdir -p $DIRECTORY
	touch $DIRECTORY/alg.file

	echo $3

	if [ ${3} = "rsa" ]; then 
		echo "create RSA keys"
		openssl genrsa -out $DIRECTORY/backend_priv_rsa.pem 2048
		openssl rsa -in $DIRECTORY/backend_priv_rsa.pem -outform PEM -pubout -out $DIRECTORY/backend_pub_rsa.pem
		echo -n "rsa" > $DIRECTORY/alg.file
	else
		echo "create ECC keys"
		openssl ecparam -name secp256r1 -genkey -noout -out $DIRECTORY/backend_priv_ecc.pem
		openssl ec -in $DIRECTORY/backend_priv_ecc.pem -pubout -out $DIRECTORY/backend_pub_ecc.pem
		echo -n "ecc" > $DIRECTORY/alg.file
	fi

	return $?

}

# TODO: This should be calculated from TPM and user nonces
function backend_createsessionhash {

	DIRECTORY=data
	mkdir -p $DIRECTORY

	HASH=$(head -c 16 /dev/urandom | xxd -p) 
	echo -n $HASH > $DIRECTORY/session.hash

	return $?
}


function backend_createderivationsecret {

	DIRECTORY=keys
	SECRET='0123456789012345'

	if [ -z ${2} ]; then 
		echo "set to default directory $DIRECTORY";
	else 
		echo "set directory to '$2'";
		DIRECTORY=$2
	fi

	if [ -z ${3} ]; then 
		SECRET=$(head -c 16 /dev/urandom)
		echo "set to default derivation secret to $SECRET";

	else
		SECRET=$3
	fi
	echo "set derivation secret to '$SECRET'";


	mkdir -p $DIRECTORY
	echo -n $SECRET > $DIRECTORY/raw.key

	return $?

}

# function backend_createsecretkey {

# 	DIRECTORY=keys
# 	SECRET='0123456789012345'

# 	if [ -z ${2} ]; then 
# 		echo "set to default directory $DIRECTORY";
# 	else 
# 		echo "set directory to '$2'";
# 		DIRECTORY=$2
# 	fi

# 	if [ -z ${3} ]; then 
# 		echo "set to default secret to $SECRET";
# 	else
# 		SECRET=$3
# 	fi
# 	echo "set secret to '$SECRET'";


# 	mkdir -p $DIRECTORY
# 	echo $SECRET > $DIRECTORY/secret.key

# 	return $?

# }

function backend_createconditionecuids {

	if [ -z ${2} ]; then 
		DIRECTORY=data
	else
		DIRECTORY=$2
	fi

	touch $DIRECTORY/ecu.ids
	echo -n "1,2,3" > $DIRECTORY/ecu.ids

	echo "set directory to '$DIRECTORY'";

}


function backend_createupdate {

	DIRECTORY=data
	# SIZE=1kB
	SIZE=1

	if [ -z ${2} ]; then 
		echo "set to default directory '$DIRECTORY'";
	else 
		echo "set directory to '$2'";
		DIRECTORY=$2
	fi

	if [ -z ${3} ]; then 
		echo "set to default update size to '$SIZE'";
	else 
		echo "set update size to '$3'";
		SIZE=$3
	fi

	mkdir -p $DIRECTORY
	head -c $SIZE /dev/urandom > $DIRECTORY/update.bin # 1G

	return $?

}


function backend_signupdate {
	DIRECTORY=data

	if [ -z ${2} ]; then 
		echo "Please provide a path to the signing key";
		return 1;
	fi

	if [ -z ${3} ]; then 
		echo "Please provide a path to the update data file";
		return 1;
	fi

	# echo "Singing Key path" ${2}
	# echo "Update data file path" ${3}
	mkdir -p $DIRECTORY
	openssl dgst -sha256 -sign ${2} -out $DIRECTORY/update.sig ${3}
	return $?
}

function backend_signpolicies {

	if [ -z ${2} ]; then 
		echo "Please provide a path to the signing key";
		return 1;
	fi

	if [ -z ${3} ]; then 
		echo "Please provide a path to rkp policy";
		return 1;
	fi

	if [ -z ${4} ]; then 
		echo "Please provide a path to iap policy";
		return 1;
	fi


	echo RKP
	xxd ${3}

	echo IAP
	xxd ${4}

	openssl dgst -sha256 -sign ${2} -out data/rkp.sig ${3}
	openssl dgst -sha256 -sign ${2} -out data/iap.sig ${4}
	return $?
}


function backend_createtemplatehash {

	if [ -z ${2} ]; then 
		echo "Please provide a path to the update data";
		return 1;
	fi

	DIRECTORY=data
	rm $DIRECTORY/template.file
	rm $DIRECTORY/template.hash
	rm $DIRECTORY/update.hash

	touch $DIRECTORY/template.file
	touch $DIRECTORY/template.hash
	touch $DIRECTORY/update.hash

	DIGEST_FIRMWARE=`openssl dgst -sha256 -binary ${2} | xxd -p -c 32`

	printf $DIGEST_FIRMWARE | xxd -r -p | dd of=$DIRECTORY/update.hash bs=1 seek=0 count=${#DIGEST_FIRMWARE} conv=notrunc

	TPM2_ALG_KEYEDHASH="0008" 					# TPMI_ALG_PUBLIC=TPM2_ALG_ID=KEYEDHASH
	TPMI_ALG_HASH="000B"						# TPM2_ALG_HASH=TPM2_ALG_ID=SHA256
	TPMA_OBJECT="00040050"						# TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDPARENT
	# TPMA_OBJECT="00040010"						# TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDPARENT
	TPM2B_DIGEST="0000"							# AUTH_POLICY
	TPMU_PUBLIC_PARMS="0005000B"				# TPMI_ALG_KEYEDHASH_SCHEME=TPM2_ALG_ID=TPM2_ALG_HMAC + TPMI_ALG_HASH=TPM2_ALG_ID=SHA256
	
	TPM2B_LABEL1="0020"`echo $DIGEST_FIRMWARE`	# LABEL: UINT16 size + TPM2_LABEL_MAX_BUFFER = 32
	TPM2B_LABEL2="0000"							# CONTEXT: UINT16 size + TPM2_LABEL_MAX_BUFFER = 32 # TODO: SID1/SID2
	TPMS_DERIVE=$TPM2B_LABEL1$TPM2B_LABEL2

	TPMT_PUBLIC=$TPM2_ALG_KEYEDHASH$TPMI_ALG_HASH$TPMA_OBJECT$TPM2B_DIGEST$TPMU_PUBLIC_PARMS$TPMS_DERIVE #"0000"

	# echo TPMT_PUBLIC
	# printf $TPMT_PUBLIC | xxd
	# echo -n $TPMT_PUBLIC | xxd -p | xxd -r
	# printf $TPMT_PUBLIC | xxd | openssl dgst -sha256 -binary -

	# DIGEST_TEMPLATE=$(printf $TPMT_PUBLIC | xxd -r | openssl dgst -sha256 -binary -)
	DIGEST_TEMPLATE=$(printf $TPMT_PUBLIC | xxd -r -p | openssl dgst -sha256 -binary -)
	# DIGEST_TEMPLATE=$(printf $TPMT_PUBLIC | xxd | tr -d \\n | openssl dgst -sha256 -binary -)

	echo DIGEST_TEMPLATE
	printf $DIGEST_TEMPLATE | xxd

	printf $TPMT_PUBLIC | xxd -r -p | dd of=$DIRECTORY/template.file bs=1 seek=0 count=$(printf "%s" "$TPMT_PUBLIC" | wc -c) conv=notrunc
	printf $DIGEST_TEMPLATE | dd of=$DIRECTORY/template.hash bs=1 seek=0 count=$(printf "%s" "$DIGEST_TEMPLATE" | wc -c) conv=notrunc
	
	return $?
}

function backend_encryptsalt {
	if [ -z ${2} ]; then 
		echo "Please provide a path to the encryption key";
	fi

	if [ -z ${3} ]; then 
		echo "Please provide a path to the update data file";
	fi

	ABC=3059301306072a8648ce3d020106082a8648ce3d0301070342`xxd -p -c 256 ${2}`

	# echo $ABC | xxd -p -r | openssl ec -pubin -inform der -in test.def -noout -text

	# openssl pkeyutl -encrypt

	return $?
}


backend_help(){
	echo "
	Usage: $(basename $0) [options] <action> <directory> [additional parameters]
	Actions:
		createbackendkeys 		Create ECC key pair
		createderivationsecret	Create derivation secret
		createupdate    		Create Update Binary
		signupdate				Sign update

	Full Example:
		[ 0. bash main_backend.sh help ]
		  1. bash main_backend.sh createbackendkeys \$PATH [keys]
		  2. bash main_backend.sh createderivationsecret \$PATH [keys]
		  3. bash main_backend.sh createsecretkey \$PATH [keys]
		  4. bash main_backend.sh createconditionecuids \$PATH [no]
		  5. bash main_backend.sh createupdate \$PATH [data] \$SIZE [1kB]
		  6. bash main_backend.sh signupdate keys/backend_priv.pem data/update.bin
		[ 7. bash main_backend.sh encryptsalt public_id.key data/salt.value ]
		[ 8. main_tpm provision and main_tpm createpolicies ]
		  9. bash main_backend.sh signpolicies keys/backend_priv.pem data/rkp.digest data/iap.digest
	"
}


backendmain() {

action="$1"

    if [ "$action" = "-h" -o "$action" = "--help" ]; then
        action=help
    fi

	backend_$action "$1" "$2" "$3" "$4"

    RET=$?
    if [ $RET -ne 0 ]; then
        echo "Error occured..."
        return $RET
    fi
    return 0


}

if [ $# -ne 0 ]; then
    backendmain "$1" "$2" "$3" "$4"
else
    true
fi




# /* Definition of TPMT_PUBLIC Structure */
# typedef struct TPMT_PUBLIC TPMT_PUBLIC;
# struct TPMT_PUBLIC {
#     TPMI_ALG_PUBLIC type;         /* algorithm associated with this object */
#     TPMI_ALG_HASH nameAlg;        /* algorithm used for computing the Name of the object NOTE The + indicates that the instance of a TPMT_PUBLIC may have a + to indicate that the nameAlg may be TPM2_ALG_NULL. */
#     TPMA_OBJECT objectAttributes; /* attributes that along with type determine the manipulations of this object */
#     TPM2B_DIGEST authPolicy;      /* optional policy for using this key. The policy is computed using the nameAlg of the object. NOTE Shall be the Empty Policy if no authorization policy is present. */
#     TPMU_PUBLIC_PARMS parameters; /* the algorithm or structure details */
#     TPMU_PUBLIC_ID unique;        /* the unique identifier of the structure. For an asymmetric key this would be the public key. */
# };
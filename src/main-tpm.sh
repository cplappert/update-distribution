#!/bin/bash

set -m # Enable job control for bg/fg

# cleanup() {
# 	echo "exit"
# 	exit 0
# }

ALG=$(cat keys/alg.file)
PERF_SBB1_FILE=perf_bash_tpm_sbb1_$ALG.txt
PERF_SBB2_FILE=perf_bash_tpm_sbb2_$ALG.txt

# trap cleanup EXIT
# trap cleanup ERR
source ./config.cfg

function tpmmain_provision {
	ALG=$(cat keys/alg.file)
	# echo $ALG
	./main_tpm --provision --raw-derivation-key keys/raw.key --pem-key keys/backend_pub_$ALG.pem --session-hash data/session.hash
}

function tpmmain_createpolicies {
	ALG=$(cat keys/alg.file)

	./main_tpm --createpolicies --session-hash data/session.hash --template-hash data/template.hash --ecu-ids data/ecu.ids

	bash main-backend.sh signpolicies keys/backend_priv_$ALG.pem data/rkp.digest data/iap.digest
}

function tpmmain_sbb1 {
	ALG=$(cat keys/alg.file)
	echo -e "RUN_SBB1,TPM,NETWORK,OVERALL[ns, $ALG]" >> $PERF_SBB1_FILE

	for ((i=1; i<=$ITERATIONS; i++))
	do
		OVERALL_START=`date +%s%N`

		# libtool --mode=execute cgdb --args \
		./main_tpm --conditionalrekeying --signature data/rkp.sig --template-hash data/template.hash \
			--session-hash data/session.hash --pem-key keys/backend_pub_$ALG.pem --update-data data/update.hash \
			--update-signature data/update.sig --out1 main-tpm-hmac.tmp

		OVERALL_END_TPM=`date +%s%N`

		cat data/update.bin | xxd -p | tr -d \\n | ncat $ECU_U_IP $ECU_U_PORT
		ncat $TPM_IP -l $TPM_PORT > /dev/null
		cat main-tpm-hmac.tmp | xxd -p | ncat $ECU_U_IP $ECU_U_PORT

		ncat $TPM_IP -l $TPM_PORT > /dev/null

		OVERALL_END=`date +%s%N`

		C1=$i
		C2=`expr $OVERALL_END_TPM - $OVERALL_START`
		C3=`expr $OVERALL_END - $OVERALL_END_TPM`
		C4=`expr $OVERALL_END - $OVERALL_START`

		echo -e "$C1,$C2,$C3,$C4" >> $PERF_SBB1_FILE

	done

	rm -f main-tpm-*.tmp
}

function tpmmain_sbb2 {
	ALG=$(cat keys/alg.file)
	touch log.txt
	echo -e "RUN_SBB2,TPM Policy,ECU_C,ECU_U,OVERALL [ns, $ALG]" >> $PERF_SBB2_FILE

	for ((i=1; i<=$ITERATIONS; i++))
	do
		ncat $TPM_IP -l $TPM_PORT | xxd -r -p > main-tpm-nonce-ecu-u.tmp

		OVERALL_START=`date +%s%N`	
expect <<EOF
	spawn sh -c "./main_tpm --authorizeinstallation --signature data/iap.sig --template-hash data/template.hash \
		--ecu-ids data/ecu.ids --update-data data/update.hash --pem-key keys/backend_pub_$ALG.pem \
		--nonce main-tpm-nonce-ecu-u.tmp --out1 main-tpm-nonce-tpm.tmp --out2 main-tpm-mac-tpm.tmp 2> log.txt"
		expect "Response Input: " {
			exec echo -n `date +%s%N` > start.tmp
 			exec cat main-tpm-nonce-tpm.tmp | xxd -p | ncat $ECU_C_IP $ECU_C_PORT
			exec ncat $TPM_IP -l $TPM_PORT | xxd -r -p > main-tpm-mac-ecu-c.tmp
			exec echo -n `date +%s%N` > end.tmp
			send "main-tpm-mac-ecu-c.tmp\r"
		}
		set ret [wait]
EOF
		POLICY_END=`date +%s%N`

		NETWORK_C_START=`cat start.tmp`
		NETWORK_C_END=`cat end.tmp`

		NETWORK_U_START=`date +%s%N`

		cat main-tpm-mac-tpm.tmp | xxd -p | ncat $ECU_U_IP $ECU_U_PORT

		ncat $TPM_IP -l $TPM_PORT > /dev/null

		OVERALL_END=`date +%s%N`

		C1=$i
		C2=$(expr $(expr $NETWORK_C_START - $OVERALL_START) + $(expr $POLICY_END - $NETWORK_C_END))
		C3=$(expr $NETWORK_C_END - $NETWORK_C_START)
		C4=$(expr $OVERALL_END - $NETWORK_U_START)
		C5=$(expr $OVERALL_END - $OVERALL_START)

		echo -e "$C1,$C2,$C3,$C4,$C5" >> $PERF_SBB2_FILE

	done

	rm -f main-tpm-*.tmp
}



tpmmain_help(){
	echo "
	Usage: $(basename $0) [options] <action> <directory> [additional parameters]
	Actions:
		provision			Provision TPM
		createpolicies		Create and Sign Policies
		sbb1				Execute SBB1
		sbb2				Execute SBB2

	Full Example:
		[ 0. bash tpmmain.sh help ]
		  1. bash tpmmain.sh provision
		  2. bash tpmmain.sh createpolicies
		  3. bash tpmmain.sh sbb1
		  4. bash tpmmain.sh sbb2
	"
}


tpmmain() {

action="$1"

    if [ "$action" = "-h" -o "$action" = "--help" ]; then
        action=help
    fi

	tpmmain_$action "$1" "$2" "$3" "$4"

    RET=$?
    if [ $RET -ne 0 ]; then
        echo "Error occured..."
        return $RET
    fi
    return 0


}

if [ $# -ne 0 ]; then
    tpmmain "$1" "$2" "$3" "$4"
else
    true
fi
#!/bin/bash

PERF_SBB1_FILE=perf_bash_ecuu_sbb1.txt
PERF_SBB2_FILE=perf_bash_ecuu_sbb2.txt

source ./config.cfg

function ecuumain_provision {
	./main_ecu --provision --key keys/raw.key
}

function ecuumain_sbb1 {

	echo -e "RUN_SBB1,ECU_U_PROCESS,OVERALL [ns]" >> $PERF_SBB1_FILE

	for ((i=1; i<=$ITERATIONS; i++))
	do
		ncat $ECU_U_IP -l $ECU_U_PORT | xxd -r -p > main-ecu-u-update.tmp

		ECU_PROCESS_1_START=`date +%s%N`

		cp main-ecu-u-update.tmp data/update.bin

		printf "done" | ncat $TPM_IP $TPM_PORT

		ECU_PROCESS_1_END=`date +%s%N`

		ncat $ECU_U_IP -l $ECU_U_PORT | xxd -r -p > main-ecu-u-mac-tpm.tmp

		ECU_PROCESS_2_START=`date +%s%N`

		./main_ecu --verify-hmac --hmac main-ecu-u-mac-tpm.tmp --update-data main-ecu-u-update.tmp

		echo -n $? | xxd -p | ncat $TPM_IP $TPM_PORT

		ECU_PROCESS_2_END=`date +%s%N`

		C1=$i
		C2=$(expr $(expr $ECU_PROCESS_1_END - $ECU_PROCESS_1_START) + $(expr $ECU_PROCESS_2_END - $ECU_PROCESS_2_START))
		C3=$(expr $ECU_PROCESS_2_END - $ECU_PROCESS_1_START)

		echo -e "$C1,$C2,$C3" >> $PERF_SBB1_FILE

	done

	rm -f main-ecu-u-*.tmp
}

function ecuumain_sbb2 {

	echo -e "RUN_SBB2,ECU_U_PROCESS,OVERALL [ns]" >> $PERF_SBB2_FILE

	for ((i=1; i<=$ITERATIONS; i++))
	do
		ECU_PROCESS_1_START=`date +%s%N`
		./main_ecu --generate-challenge --out main-ecu-u-nonce-ecu-u.tmp
		cat main-ecu-u-nonce-ecu-u.tmp | xxd -p | ncat $TPM_IP $TPM_PORT
		ECU_PROCESS_1_END=`date +%s%N`
		
		ncat $ECU_U_IP -l $ECU_U_PORT | xxd -r -p > main-ecu-u-mac-tpm.tmp

		ECU_PROCESS_2_START=`date +%s%N`
		./main_ecu --authorize-installation --tpm-hmac main-ecu-u-mac-tpm.tmp --update-data data/update.bin
		echo -n $? | xxd -p | ncat $TPM_IP $TPM_PORT
		ECU_PROCESS_2_END=`date +%s%N`

		C1=$i
		C2=$(expr $(expr $ECU_PROCESS_1_END - $ECU_PROCESS_1_START) + $(expr $ECU_PROCESS_2_END - $ECU_PROCESS_2_START))
		C3=$(expr $ECU_PROCESS_2_END - $ECU_PROCESS_1_START)

		echo -e "$C1,$C2,$C3" >> $PERF_SBB2_FILE

	done

	rm -f main-ecu-u-*.tmp
}



ecuumain_help(){
	echo "
	Usage: $(basename $0) [options] <action> <directory> [additional parameters]
	Actions:
		provision			Provision ECU
		sbb1				Execute SBB1
		sbb2				Execute SBB2

	Full Example:
		[ 0. bash ecuumain.sh help ]
		  1. bash ecuumain.sh provision
		  2. bash ecuumain.sh createpolicies
		  3. bash ecuumain.sh sbb1
		  4. bash ecuumain.sh sbb2
	"
}


ecuumain() {

action="$1"

    if [ "$action" = "-h" -o "$action" = "--help" ]; then
        action=help
    fi

	ecuumain_$action "$1" "$2" "$3" "$4"

    RET=$?
    if [ $RET -ne 0 ]; then
        echo "Error occured..."
        return $RET
    fi
    return 0


}

if [ $# -ne 0 ]; then
    ecuumain "$1" "$2" "$3" "$4"
else
    true
fi
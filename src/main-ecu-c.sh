#!/bin/bash

PERF_SBB2_FILE=perf_ecuc_sbb2.txt

source ./config.cfg

function ecucmain_provision {
	./main_ecu --provision --key keys/raw.key
}

function ecucmain_sbb2 {

	echo -e "RUN_SBB2,ECU_C_PROCESS,OVERALL [ns]" >> $PERF_SBB2_FILE

	for ((i=1; i<=$ITERATIONS; i++))
	do
		ncat $ECU_C_IP -l $ECU_C_PORT | xxd -r -p > main-ecu-c-nonce-tpm.tmp

		ECU_PROCESS_1_START=`date +%s%N`
		./main_ecu --answer-challenge --kdf-input data/ecu.ids --challenge main-ecu-c-nonce-tpm.tmp --out main-ecu-c-mac-ecu-c.tmp
		cat main-ecu-c-mac-ecu-c.tmp | xxd -p | ncat $TPM_IP $TPM_PORT
		ECU_PROCESS_1_END=`date +%s%N`

		C1=$i
		C2=$(expr $ECU_PROCESS_1_END - $ECU_PROCESS_1_START)
		C3=$C2

		echo -e "$C1,$C2,$C3" >> $PERF_SBB2_FILE

	done

	rm -f main-ecu-c-*.tmp
}



ecucmain_help(){
	echo "
	Usage: $(basename $0) [options] <action> <directory> [additional parameters]
	Actions:
		provision			Provision ECU
		sbb1				Execute SBB1
		sbb2				Execute SBB2

	Full Example:
		[ 0. bash main-ecu-c.bash help ]
		  1. bash main-ecu-c.bash provision
		  2. bash main-ecu-c.bash sbb2
	"
}


ecucmain() {

action="$1"

    if [ "$action" = "-h" -o "$action" = "--help" ]; then
        action=help
    fi

	ecucmain_$action "$1" "$2" "$3" "$4"

    RET=$?
    if [ $RET -ne 0 ]; then
        echo "Error occured..."
        return $RET
    fi
    return 0


}

if [ $# -ne 0 ]; then
    ecucmain "$1" "$2" "$3" "$4"
else
    true
fi
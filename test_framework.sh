#!/bin/bash

trap stop SIGINT SIGKILL SIGTERM
trap 'if [[ $? -eq 139 ]]; then segfault(); fi' SIGCHLD 

function stop(){
    echo "#### CTRL+C ####"
    exit 1
}

function segfault(){
    echo "#### SEGFAULT ####"
    exit 1
}

thisDir=$(realpath $0 | xargs dirname)


if [[ "$thisDir" == *"IMX8_QXP_B0"* ]]; then
    BOARD=fsl-imx8qxp-b0-mek-linux.nxp-open
    DEVICE=IMX8_QXP_B0
elif [[ "$thisDir" == *"IMX8_QM_B0"* ]]; then
    BOARD=fsl-imx8qm-ddr4-arm2-linux.nxp-open
    DEVICE=IMX8_QM_B0
fi


# Build the test list

# Act on argument(s)
ret_code=0
case $1 in

  list)
    testlist=$(cat ${thisDir}/testlist)
    for test in "${testlist[@]}"; do
        echo "${test}"
    done
    ;;

  run)
    testname=$2
    logdir="$(pwd)"
    $thisDir/run_tests -s "${testname}" 2>&1 | tee ${logdir}/output.log
    ret_code=${PIPESTATUS[0]}
    echo -e "\n<summary>" > ${logdir}/summary.log
    more ${logdir}/output.log | grep -E 'test: |\-\->' | awk -F"test: |-->" '{ print $2 }' >> ${logdir}/summary.log
    echo "</sumary>" >> ${logdir}/summary.log
    echo -e "\nError Code = ${ret_code}" >> ${logdir}/summary.log
    cat ${logdir}/summary.log | tee -a ${logdir}/output.log
    ;;

  describe)
    echo "# describe: Not supported!"

TESTNAME="${testname}"
PLATFORM="BOARD"
REBOOT="1"
RUN_TEST="run_tests -s '${testname}'"
DEVICE="${DEVICE}"
BOARD="${BOARD}"

BLOCK
    ;;

   *)
    cmd=$(basename $0)
    echo "Usage:"
    echo "  ${cmd} list"
    echo "  ${cmd} describe <testcase>"
    echo "  ${cmd} run <testcase>"
    ;;

esac

exit ${ret_code}

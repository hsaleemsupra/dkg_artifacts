#!/bin/bash

reports_root="Report"
tar_logs="tar_logs"

extract() {
    sources=$(ls ${1}/*.tar.gz)
    logs=${2}
    for compressed_file in ${sources}
    do
        tar xf  ${compressed_file} -C ${logs}
    done
}


echo "Extracting logs ..."
tarballs=$(ls ${reports_root}/*/${tar_logs} -d)
for tarball in ${tarballs}
do
    simulation=$(dirname ${tarball})
    pushd ${simulation}
    rm -rf logs
    mkdir logs
    extract $(basename ${tarball}) logs
    popd
done
echo "Extracting logs ... Done"

#!/bin/bash

size="500000 1000000 2000000"
clans="1"
broadcasters="7"
config=chain_parameters_t1_c5_n7.json
reports_root="Report"
tar_logs="tar_logs"

for s in ${size}; do
    v1=$(jq --argjson s "$s" '.batch_config.size_in_bytes = $s' ${config})
    for bc in ${clans}; do
        v2=$(echo "${v1}" | jq --argjson bc "$bc" '.network_config.proposers_per_tribe = $bc')
        for b in ${broadcasters}; do
            v3=$(echo "${v2}" | jq --argjson b "$b" '.network_config.proposers_per_clan = $b')
            echo -e "${v3}" >  ${config}
            simulation="S_${s}_${bc}_${b}"
            echo "Running simulation: ${simulation}"
            report_dir=${reports_root}/${simulation}
            rm -rf "${report_dir}"
            mkdir -p "${report_dir}"
            fab remote -c ${config}
            fab stop-nodes -c ${config}
            mv logs "${report_dir}/${tar_logs}"
            cp ${config} "${report_dir}"
            cp configs/faulty_peers.json "${report_dir}"
            echo "Done simulation: ${simulation}"
        done
    done
done

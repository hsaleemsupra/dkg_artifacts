#!/usr/bin/python3
import os
import shutil
import stat
import sys
from collections import defaultdict
import subprocess

import pandas as pd

from utilities.utils import with_size_postfix
from utilities.metrics import Metrics

report = "Report"
work_dir = "wk_dir"


def extruct_leaders(logs_dir):
    """
    :param logs_dir: logs dir path
    :return: list of ids of leaders deduced from logs
    """
    script = """#!/bin/bash
        src=${1}
        if [ -z "${src}" ]; then
            echo "log directory should be specified as first argument"
            exit 1
        fi

        leader_pattern="Leader, [[:alnum:]]*,"

        filter_leaders() {
            sources=$1
            leaders=$(grep -Eoh -m 1 "${leader_pattern}" -R ${sources} | cut -d "," -f2)
            echo ${leaders}
        }

        filter_leaders ${src}
    """
    script_name = "./extract_leader.sh"
    with open(script_name, "w") as file:
        file.write(script)
    os.chmod(script_name, stat.S_IRWXG | stat.S_IRWXU)
    result = run_shell_script(["./%s %s" % (script_name, logs_dir)])
    os.remove(script_name)
    return list(result.split())

def filter_metrics(logs_dir, dest, pattern):
    """
    :param logs_dir: dir path to logs
    :param dest: destination folder to keep the filtered metrics
    :param pattern: pattern based on which filtering should be done
    :return: output directory path of the filtered metrics
    """
    script = """#!/bin/bash
            src=${1}
            if [ -z "${src}" ]; then
                echo "log directory should be specified as first argument"
                exit 1
            fi

            dest=${2}
            if [ -z "${dest}" ]; then
                echo "dest id be specified as second argument"
                exit 1
            fi

            pattern=\"%s\"

            # filter metrics from logs
            metric_root="${src}/../wk_dir/"
            dest="${metric_root}/${dest}"
            rm -rf ${dest}
            mkdir -p ${dest}

            filter_metrics() {
                local src=${1}
                src_base=$(basename ${src})
                if [ -d ${src} ] && ! [[ "${src}" == *"${metric_root}"* ]] ; then
                    content=$(ls -d ${src}/*)
                    for file in ${content}
                    do
                        filter_metrics ${file}
                    done
                elif [ -f ${src} ]; then
                    dest_file=${dest}/${src_base}
                    grep "${pattern}" ${src} > ${dest_file}
                fi
            }
            filter_metrics ${src}
            echo ${dest}
    """ % pattern
    script_name = "./filter_metric.sh"
    with open(script_name, "w") as file:
        file.write(script)
    os.chmod(script_name, stat.S_IRWXG | stat.S_IRWXU)
    result = run_shell_script(["%s %s %s" % (script_name, logs_dir, dest)])
    os.remove(script_name)
    return result


def filter_metrics_by_leader(logs_dir, leader):
    """
    :param logs_dir: dir path to logs
    :param leader: leader id to filter metrics
    :return: output directory path of the filtered metrics
    """
    pattern = "INFO\s*(METRIC).*MessageMeta ([[:alnum:]]*, %s), [[:alnum:]]*)" % leader
    return filter_metrics(logs_dir, leader, pattern)

def filter_metrics_by_name(logs_dir, metric_name):
    """
    :param logs_dir: dir path to logs
    :param leader: leader id to filter metrics
    :return: output directory path of the filtered metrics
    """
    pattern = "INFO\s*(METRIC)\] %s" % metric_name
    return filter_metrics(logs_dir, "system", pattern)


def run_shell_script(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, shell=True, text=True)
    return result.stdout


def all_metrics(log_name, pattern=None):
    metrics_inner = Metrics(reg_exp_pattern=pattern)
    with open(log_name, "r+") as log_file:
        for line in log_file:
            metrics_inner.collect_metric(line)
    return metrics_inner


def merge_by_max(agg: dict, summary):
    for k, v in summary.items():
        agg.setdefault(k, 0)
        agg[k] = max(agg[k], v)

def merge(agg: dict, summary):
    for k, v in summary.items():
        key_min = f"{k}-min"
        key_avg = f"{k}-avg"
        key_max = f"{k}-max"
        agg.setdefault(key_min, sys.float_info.max)
        agg.setdefault(key_avg, v)
        agg.setdefault(key_max, sys.float_info.min)

        agg[key_min] = min(agg[key_min], v)
        agg[key_avg] = (agg[key_avg] + v) / 2
        agg[key_max] = max(agg[key_max], v)

def calculate_throughput(log_dir, wk_dir, measure = 1.0):
    system_metrics_dir = os.path.join(wk_dir, "system")
    output_dir = system_metrics_dir
    if not os.path.exists(system_metrics_dir):
        output_dir = filter_metrics_by_name(log_dir, "system")
    print("System metrics here: %s - %s" % (output_dir, system_metrics_dir))
    summary = dict()
    for log_name in os.listdir(system_metrics_dir):
        log_file = os.path.join(system_metrics_dir, log_name)
        metrics_inner = all_metrics(log_file, Metrics.SYSTEM_REG_EXP)
        throughput = metrics_inner.throughput(measure)
        merge(summary, throughput)
    return summary

def handle_logs(log_root, measure = 1.0):
    log_dir = os.path.join(report, log_root, "logs")
    wk_dir = os.path.join(report, log_root, work_dir)

    if os.path.exists(wk_dir):
        shutil.rmtree(wk_dir)

    throughput = calculate_throughput(log_dir, wk_dir, measure)

    leaders = extruct_leaders(log_dir)
    summary = dict()
    for leader in leaders:
        leader_metrics_dir = os.path.join(wk_dir, leader)
        output_dir = leader_metrics_dir
        if not os.path.exists(leader_metrics_dir):
            output_dir = filter_metrics_by_leader(log_dir, leader)
        print("Leader based metrics here: %s - %s" % (output_dir, leader_metrics_dir))

        experiment_metric = Metrics()
        for log_name in os.listdir(leader_metrics_dir):
            metrics_inner = all_metrics(os.path.join(leader_metrics_dir, log_name))
            experiment_metric.extend(metrics_inner)
        #merge_by_max(summary, experiment_metric.single_data_summary())
        merge_by_max(summary, experiment_metric.summary())
    return summary, throughput


if __name__ == "__main__":
    size_metrics = defaultdict(dict)
    time_metrics = defaultdict(dict)
    other_metrics = defaultdict(dict)
    throughput = defaultdict(dict)
    for log_root_dir in os.listdir(report):
        if not os.path.isdir("%s/%s" %(report,log_root_dir)):
            print("Skip", log_root_dir)
            continue

        details = log_root_dir.split("_")
        summary, throughput_data = handle_logs(log_root_dir, float(details[1]) / 1000000.0)

        simulation_key = f"{with_size_postfix(details[1])}_{details[2]}C{details[3]}B"
        simulation_key = f"{details[0]}{with_size_postfix(details[1])}_{details[2]}C{details[3]}B"


        size_metrics.setdefault(simulation_key, dict())
        time_metrics.setdefault(simulation_key, dict())
        other_metrics.setdefault(simulation_key, dict())
        throughput.setdefault(simulation_key, throughput_data)
        for k in summary.keys():
            value = dict({k: summary[k]})
            if "message-size" in k:
                size_metrics[simulation_key].setdefault(k, summary[k])
            elif "travel-time" in k:
                time_metrics[simulation_key].setdefault(k, summary[k])
            else:
                other_metrics[simulation_key].setdefault(k, summary[k])

    size_metrics = pd.DataFrame(size_metrics)
    time_metrics = pd.DataFrame(time_metrics)
    other_metrics = pd.DataFrame(other_metrics)
    throughput = pd.DataFrame(throughput)

    size_metrics.to_csv("size_metrics.csv", encoding='utf-8')
    time_metrics.to_csv("time_metrics.csv", encoding='utf-8')
    other_metrics.to_csv("delivery_metrics.csv", encoding='utf-8')
    throughput.to_csv("throughput_metrics.csv", encoding='utf-8')

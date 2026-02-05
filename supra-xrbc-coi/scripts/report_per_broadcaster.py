#!/usr/bin/python3
import os
import shutil
from collections import defaultdict

import pandas as pd

from report import extruct_leaders, filter_metrics_by_leader, all_metrics, report, work_dir
from utilities.utils import with_size_postfix
from utilities.metrics import Metrics


def handle_logs(log_root):
    log_dir = os.path.join(report, log_root, "logs")
    wk_dir = os.path.join(report, log_root, work_dir)

    if os.path.exists(wk_dir):
        shutil.rmtree(wk_dir)

    leaders = extruct_leaders(log_dir)
    for leader in leaders:
        output_dir = filter_metrics_by_leader(log_dir, leader)
        leader_metrics_dir = os.path.join(wk_dir, leader)
        print("Leader based metrics here: %s - %s" % (output_dir, leader_metrics_dir))

        experiment_metric = Metrics()
        for log_name in os.listdir(leader_metrics_dir):
            metrics_inner = all_metrics(os.path.join(leader_metrics_dir, log_name))
            experiment_metric.extend(metrics_inner)
        dump_metrics(leader_metrics_dir, experiment_metric.summary())


def dump_metrics(leader_dir, summary):
    size_metrics = defaultdict(dict)
    time_metrics = defaultdict(dict)
    other_metrics = defaultdict(dict)

    details = leader_dir.split("_")
    simulation_key = f"{with_size_postfix(details[1])}_{details[2]}C{details[3]}B"

    size_metrics.setdefault(simulation_key, dict())
    time_metrics.setdefault(simulation_key, dict())
    other_metrics.setdefault(simulation_key, dict())
    for k in summary.keys():
        if "message-size" in k:
            size_metrics[simulation_key].setdefault(k, summary[k])
        elif "travel-time" in k:
            time_metrics[simulation_key].setdefault(k, summary[k])
        else:
            other_metrics[simulation_key].setdefault(k, summary[k])

    size_metrics = pd.DataFrame(size_metrics)
    time_metrics = pd.DataFrame(time_metrics)
    other_metrics = pd.DataFrame(other_metrics)

    size_metrics.to_csv(os.path.join(leader_dir, "size_metrics.csv"), encoding='utf-8')
    time_metrics.to_csv(os.path.join(leader_dir, "time_metrics.csv"), encoding='utf-8')
    other_metrics.to_csv(os.path.join(leader_dir, "delivery_metrics.csv"), encoding='utf-8')


if __name__ == "__main__":
    for log_root_dir in os.listdir(report):
        handle_logs(log_root_dir)

import re

SECOND_IN_NS = 1000000000

class Metrics:
    METRIC_REG_EXP = ".*\(METRIC\)\] (?P<tag>[a-z\-]*) \- (?P<value>[0-9\.]*) [bns] \- \[(?P<target>\w+)\s*\(.*\)(, (?P<extra_tag>.*))?\]"
    SYSTEM_REG_EXP = ".*\(METRIC\)\] ([a-z\-]*)(?P<tag>system-data[a-z\-]*) \- (?P<value>[0-9\.]*) [bns]"

    def __init__(self, reg_exp_pattern=None):
        self.metrics = dict()
        if reg_exp_pattern:
            self.reg_exp = re.compile(reg_exp_pattern)
        else:
            self.reg_exp = re.compile(Metrics.METRIC_REG_EXP)

    def summary(self):
        entry = dict()

        for k in self.metrics.keys():
            v = self.metrics[k]
            for t in v.keys():
                values = v[t]
                if "system-data" in k:
                    continue

                min_key = "%s (MIN)[%s]" % (k, t)
                avg_key = "%s (AVG)[%s]" % (k, t)
                max_key = "%s (MAX)[%s]" % (k, t)
                count = "%s (COUNT)[%s]" % (k, t)

                entry.setdefault(min_key, min(values))
                entry.setdefault(avg_key, sum(values) / len(values))
                entry.setdefault(max_key, max(values))
                entry.setdefault(count, len(values))
        return entry

    def single_data_summary(self, index=5):
        entry = dict()

        for k in self.metrics.keys():
            v = self.metrics[k]
            for t in v.keys():
                values = v[t]
                if "system-data" in k:
                    # continue
                    input_throughput = "%s (THROUGHPUT)[%s]" % (k, t)
                    entry.setdefault(input_throughput, (max(values) - min(values))/len(values))

                min_key = "%s (MIN)[%s]" % (k, t)
                avg_key = "%s (AVG)[%s]" % (k, t)
                max_key = "%s (MAX)[%s]" % (k, t)
                count = "%s (COUNT)[%s]" % (k, t)

                idx = min(index, len(values) - 1)

                entry.setdefault(min_key, min(values))
                entry.setdefault(avg_key, values[idx])
                entry.setdefault(max_key, max(values))
                entry.setdefault(count, len(values))
        return entry

    def throughput(self, measure=1.0):
        entry = dict()

        for k in self.metrics.keys():
            v = self.metrics[k]
            for t in v.keys():
                values = v[t]
                count = "%s (COUNT)[%s]" % (k, t)
                throughput_key = "%s (throughput)[%s]" % (k, t)

                min_value = min(values)
                max_value = max(values)
                throughput = (max_value - min_value) / SECOND_IN_NS
                entry.setdefault(throughput_key,  (measure * len(values))/throughput)
                entry.setdefault(count, len(values))
        return entry

    def extend(self, other):
        for k in other.metrics.keys():
            v = other.metrics[k]
            for t in v.keys():
                self.metrics.setdefault(k, dict())
                self.metrics[k].setdefault(t, list())
                self.metrics[k][t].extend(v[t])

    def collect_metric(self, line):
        groups = self.reg_exp.match(line)
        if groups is None:
            return
        tag = groups.group("tag")
        value = groups.group("value")
        target = None
        if "target" in groups.groupdict().keys():
            target = groups.group("target")
        extra_tag = None
        if "extra_tag" in groups.groupdict().keys():
            extra_tag = groups.group("extra_tag")

        key = tag
        if extra_tag:
            key = "%s-%s" % (extra_tag, tag)
        self.metrics.setdefault(key, dict())
        self.metrics[key].setdefault(target, list())
        self.metrics[key][target].append(float(value))

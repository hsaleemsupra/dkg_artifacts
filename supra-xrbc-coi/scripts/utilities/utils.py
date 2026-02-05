from os.path import join
from json import dump


class BenchError(Exception):
    def __init__(self, message, error=None):
        # assert isinstance(error, Exception)
        self.message = message
        self.cause = error
        super().__init__(message)


def dump_json(filename, data):
    assert isinstance(filename, str)
    with open(filename, 'w') as f:
        dump(data, f, indent=4, sort_keys=True)


class PathMaker:
    @staticmethod
    def binary_path():
        return join('..', 'target', 'release')

    @staticmethod
    def binary_name():
        return "supra-node"

    @staticmethod
    def config_dir_path():
        return "configs"

    @staticmethod
    def node_crate_path():
        return join('..', 'node')

    @staticmethod
    def peers_file():
        return 'peers.json'

    @staticmethod
    def faulty_peers_file():
        return 'faulty_peers.json'

    @staticmethod
    def parameters_file():
        return 'chain_parameters.json'

    @staticmethod
    def suffix(t, c, p, ip):
        assert isinstance(t, int) and t >= 0
        assert isinstance(c, int) and c >= 0
        assert isinstance(p, int) and p >= 0
        if ip:
            ip = f'_{ip}'
        return f'{t}_{c}_{p}{ip}'

    @staticmethod
    def key_file(t, c, p, ip):
        suffix = PathMaker.suffix(t, c, p, ip)
        return f'node_{suffix}.json'

    @staticmethod
    def logs_path():
        return 'logs'

    @staticmethod
    def node_log_file(t, c, p, ip=''):
        suffix = PathMaker.suffix(t, c, p, ip)
        return join(PathMaker.logs_path(), f'log_{suffix}.log')

    @staticmethod
    def node_key_file(t, c, p, ip=''):
        return join(PathMaker.config_dir_path(), PathMaker.key_file(t, c, p, ip))

    @staticmethod
    def network_config_file():
        return join(PathMaker.config_dir_path(), "network_config.json")

    @staticmethod
    def host_ips_file():
        return join(PathMaker.config_dir_path(), "hosts.json")

    @staticmethod
    def chain_parameters_file():
        return join(PathMaker.config_dir_path(), PathMaker.parameters_file())

    @staticmethod
    def chain_peers_file():
        return join(PathMaker.config_dir_path(), PathMaker.peers_file())

    @staticmethod
    def chain_faulty_peers_file():
        return join(PathMaker.config_dir_path(), PathMaker.faulty_peers_file())

class Color:
    HEADER = '\033[95m'
    OK_BLUE = '\033[94m'
    OK_GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Print:
    @staticmethod
    def heading(message):
        assert isinstance(message, str)
        print(f'{Color.OK_GREEN}{message}{Color.END}')

    @staticmethod
    def info(message):
        assert isinstance(message, str)
        print(message)

    @staticmethod
    def warn(message):
        assert isinstance(message, str)
        print(f'{Color.BOLD}{Color.WARNING}WARN{Color.END}: {message}')

    @staticmethod
    def error(e):
        assert isinstance(e, BenchError)
        print(f'\n{Color.BOLD}{Color.FAIL}ERROR{Color.END}: {e}\n')
        causes, current_cause = [], e.cause
        while isinstance(current_cause, BenchError):
            causes += [f'  {len(causes)}: {e.cause}\n']
            current_cause = current_cause.cause
        causes += [f'  {len(causes)}: {type(current_cause)}\n']
        causes += [f'  {len(causes)}: {current_cause}\n']
        print(f'Caused by: \n{"".join(causes)}\n')


def progress_bar(iterable, prefix='', suffix='', decimals=1, length=30, fill='█', print_end='\r'):
    total = len(iterable)

    def printProgressBar(iteration):
        formatter = '{0:.' + str(decimals) + 'f}'
        percent = formatter.format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)

    printProgressBar(0)
    for i, item in enumerate(iterable):
        yield item
        printProgressBar(i + 1)
    print()


def with_size_postfix(size_in_bytes):
    size_in_bytes = int(size_in_bytes)
    if size_in_bytes < 1000000:
        return str(size_in_bytes // 1000) + "KB"
    else:
        return str(size_in_bytes // 1000000) + "MB"

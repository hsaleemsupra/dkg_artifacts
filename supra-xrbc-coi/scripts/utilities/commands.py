from os.path import join
import os

from utilities.utils import PathMaker


class CommandMaker:

    @staticmethod
    def cleanup():
        return f'rm -fr {PathMaker.config_dir_path()} '

    @staticmethod
    def clean_logs():
        return f'rm -fr {PathMaker.logs_path()} ; mkdir -p {PathMaker.logs_path()}'

    @staticmethod
    def compile():
        return 'cargo build --quiet --release'

    @staticmethod
    def generate_key(network_params, destination, fault_percent, remote_ips=''):
        assert isinstance(network_params, str)
        assert isinstance(destination, str)
        assert isinstance(remote_ips, str)
        assert isinstance(fault_percent, str)
        return f'./{PathMaker.binary_name()} generate {network_params} {destination} {fault_percent} {remote_ips}'

    @staticmethod
    def run_node(chain_params, identity, peers, debug=False):
        assert isinstance(chain_params, str)
        assert isinstance(identity, str)
        assert isinstance(peers, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        # return f'echo "./{PathMaker.binary_name()} {v} run {chain_params} {identity} {peers}"'
        return f'./{PathMaker.binary_name()} {v} run {chain_params} {identity} {peers}'

    @staticmethod
    def make_dir(path):
        os.makedirs(path, exist_ok=True)

    @staticmethod
    def make_dir_cmd(path):
        return f'mkdir -p {path}'

    @staticmethod
    def alias_binaries(origin):
        assert isinstance(origin, str)
        node = join(origin, PathMaker.binary_name())
        return f'rm {PathMaker.binary_name()} ; ln -s {node} {PathMaker.binary_name()}'
    @staticmethod
    def kill():
        return f'tmux kill-server'

import subprocess
import os
from pathlib import Path
from time import sleep
import psutil
from utilities.commands import CommandMaker
from utilities.config import ChainParameters, ConfigError
from utilities.faulty_node import FaultyNodeIdentifier
from utilities.utils import Print, BenchError, PathMaker


def start_broadcasting():
    Path(".chain_ready").touch()
    Print.info("hosts are updated with .chain_ready file")


def stop_broadcasting():
    os.remove(".chain_ready")
    Print.info("hosts are updated with no .chain_ready file")


class LocalRunner:

    def __init__(self, params, reuse, dry_run, duration=30, debug=False):
        try:
            self.chain_parameters = ChainParameters.load(params)
            self.reuse = reuse
            self.dry_run = dry_run
            self.duration = duration
            self.debug = debug
        except ConfigError as e:
            raise BenchError('Invalid chain parameters', e)

    def __getattr__(self, attr):
        return getattr(self.chain_parameters, attr)

    def _kill_nodes(self):
        bin_name = PathMaker.binary_name()
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            if bin_name in proc.info['name']:
                proc.kill()

    def _generate_configs(self):
        if self.reuse:
            return
        chain_config = PathMaker.chain_parameters_file()
        nt_config = PathMaker.network_config_file()
        output = PathMaker.config_dir_path()
        fault_percent = os.environ.get("FAULT_PERCENT")
        CommandMaker.make_dir(output)
        self.chain_parameters.print(chain_config)
        self.chain_parameters.print_network_config(nt_config)
        cmd = CommandMaker.generate_key(nt_config, output, fault_percent)
        Print.info(f'Generating configs {cmd}...')
        try:
            subprocess.check_output(cmd, shell=True)
            sleep(0.5)  # Generation may take some time
        except subprocess.SubprocessError as e:
            raise BenchError('Failed to generate configs', e)

    def _start_chain(self):
        CommandMaker.make_dir(PathMaker.logs_path())
        chain_params = PathMaker.chain_parameters_file()
        peers = PathMaker.chain_peers_file()
        faulty_peers = PathMaker.chain_faulty_peers_file()
        if not os.path.exists(chain_params) or not os.path.exists(peers) or not os.path.exists(faulty_peers):
            raise BenchError('Not all config files are present')
        try:
            self._start_tribes(chain_params, peers)
        except BenchError as e:
            self._kill_nodes()
            raise BenchError('Failed to start chain', e)

    def _start_tribes(self, chain_params, peers):
        for t in range(self.chain_parameters.tribes()):
            self._start_clans(t, chain_params, peers)

    def _start_clans(self, tribe, chain_params, peers):
        for c in range(self.chain_parameters.clans()):
            self._start_clan(tribe, c, chain_params, peers)

    def _start_clan(self, tribe, clan, chain_params, peers):
        faulty = FaultyNodeIdentifier.load(PathMaker.chain_faulty_peers_file()).faulty_identy
        try:
            for p in range(self.chain_parameters.peers()):
                node_key = PathMaker.node_key_file(tribe, clan, p)
                if int(os.environ.get("PASSIVE_OR_CRASHED")) == 1 and node_key in faulty:
                    continue
                if not os.path.exists(node_key):
                    raise BenchError(f'Missing {node_key} file')
                node_cmd = CommandMaker.run_node(chain_params, node_key, peers, self.debug)
                log_file = PathMaker.node_log_file(tribe, clan, p)
                cmd = f'{node_cmd} >  {log_file} 2>&1 &'
                Print.info(f'Running {cmd}')
                if not self.dry_run:
                    subprocess.check_output(cmd, shell=True)
        except (subprocess.SubprocessError, BenchError) as e:
            raise BenchError(f'Failed to start node of {tribe}-{clan} clan', e)

    def run(self):
        Print.heading('Starting local run')

        # Kill any previous testbed.
        self._kill_nodes()

        try:
            Print.info('Setting up testbed...')

            # Cleanup all files.
            cmd = f'{CommandMaker.clean_logs()}'
            if not self.reuse:
                cmd = f'{cmd} ; {CommandMaker.cleanup()}'
            Print.info(f'Cleaning env {cmd}...')
            subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)
            sleep(0.5)  # Removing the store may take time.

            # Recompile the latest code.
            cmd = CommandMaker.compile().split()
            Print.info(f'Compiling binary {cmd}...')
            subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

            # Create alias for the client and nodes binary.
            cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
            Print.info(f'Alias binary {cmd}...')
            subprocess.run([cmd], shell=True)

            self._generate_configs()

            self._start_chain()

            if not self.dry_run:
                Print.info(f'Running benchmark ({self.duration} sec)...')
                start_broadcasting()
                sleep(self.duration)
                stop_broadcasting()
                self._kill_nodes()
            else:
                Print.info(f'Running benchmark in dry-run mode ...')

        except subprocess.SubprocessError as e:
            self._kill_nodes()
            raise BenchError('Failed to run benchmark', e)

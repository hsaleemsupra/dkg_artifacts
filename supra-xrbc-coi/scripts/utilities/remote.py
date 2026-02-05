import glob
import os.path
import subprocess
from time import sleep
from fabric import Connection, ThreadingGroup as Group
from fabric.exceptions import GroupException
from paramiko import RSAKey
from paramiko.ssh_exception import PasswordRequiredException, SSHException
from os.path import basename, splitext
from pathlib import Path
from utilities.commands import CommandMaker
from utilities.faulty_node import FaultyNodeIdentifier
from utilities.instance import InstanceManager
from utilities.utils import BenchError, Print, PathMaker, dump_json, progress_bar
from utilities.config import ChainParameters

DEFAULT_DELAY = 10
THREAD_COUNT = 8
from multiprocessing.pool import ThreadPool


class FabricError(Exception):
    ''' Wrapper for Fabric exception with a meaningful error message. '''

    def __init__(self, error):
        assert isinstance(error, GroupException)
        message = list(error.result.values())[-1]
        super().__init__(message)


class ExecutionError(Exception):
    pass


class Bench:
    def __init__(self, ctx):
        self.chain_parameters = None
        self.duration = None
        self.debug = None
        self.reuse = None
        self.dry_run = None
        self.manager = InstanceManager.make()
        self.settings = self.manager.settings
        try:
            ctx.connect_kwargs.pkey = RSAKey.from_private_key_file(
                self.manager.settings.instance_key
            )
            self.connect = ctx.connect_kwargs
        except (IOError, PasswordRequiredException, SSHException) as e:
            raise BenchError('Failed to load SSH key', e)

    def initialize(self, chain_parameters, duration, debug, reuse, dry_run):
        self.chain_parameters = ChainParameters.load(chain_parameters)
        self.duration = duration
        self.debug = debug
        self.reuse = reuse
        self.dry_run = dry_run

    def _check_stderr(output):
        if isinstance(output, dict):
            for x in output.values():
                if x.stderr:
                    raise ExecutionError(x.stderr)
        else:
            if output.stderr:
                raise ExecutionError(output.stderr)

    def reinstall(self):
        Print.info('Removing previous repo and cloning the fresh repo...')
        cmd = [
            'rm -rf supra-xrbc-coi',
            # Clone the repo.
            f'(GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git clone {self.settings.repo_url} || (cd {self.settings.repo_name} ; git pull))'
        ]
        try:
            hosts = self.manager.hosts(flat=True)
            g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
            # Copy the Deploy Key to /home/ubuntu
            g.put(self.settings.github_deploy_key_path)
            # Assume the public key has the same name as the private key with '.pub' appended
            g.put(self.settings.github_deploy_key_path + '.pub')
            g.put(".env")
            # Run the installation script
            g.run(' && '.join(cmd), hide=True)
            Print.heading(f'Initialized testbed of {len(hosts)} nodes')
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError('Failed to install repo on testbed', e)

    def install(self):
        Print.info('Installing rust and cloning the repo...')
        deploy_key = self.settings.github_deploy_key_name
        cmd = [
            'sudo sysctl -w net.ipv4.tcp_tw_reuse=1',
            'sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 33554432"',
            'sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 33554432"',
            'sudo sysctl -w net.core.somaxconn=2147483647',

            '''printf "* soft     nproc          65535 \n\
            * hard     nproc          65535 \n\
            * soft     nofile         65535 \n\
            * hard     nofile         65535 \n\
            root soft     nproc          65535 \n\
            root hard     nproc          65535 \n\
            root soft     nofile         65535 \n\
            root hard     nofile         65535\n" | sudo tee -a /etc/security/limits.conf''',

            # Move the previously-copied deploy key to its proper location and set it
            # as the default for GitHub.
            f'mv /home/ubuntu/{deploy_key}* /home/ubuntu/.ssh',
            f'chmod 400 /home/ubuntu/.ssh/{deploy_key}*',
            f'''echo -e \
                "Host github.com\n  HostName github.com\n  IdentityFile ~/.ssh/{deploy_key}" \
                > /home/ubuntu/.ssh/config''',
            'eval $(ssh-agent)',
            f'ssh-add /home/ubuntu/.ssh/{deploy_key}',

            'sudo apt-get update',
            'sudo apt-get -y upgrade',
            'sudo apt-get -y autoremove',

            # The following dependencies prevent the error: [error: linker `cc` not found].
            'sudo apt-get -y install build-essential',
            'sudo apt-get -y install cmake',

            # The following dependencies prevent the build error return from influxdb2
            'sudo apt-get -y install pkg-config',
            'sudo apt-get -y install libssl-dev',

            # Install rust (non-interactive).
            'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y',
            'source $HOME/.cargo/env',
            'rustup default stable',

            # This is missing from the Rocksdb installer (needed for Rocksdb).
            'sudo apt-get install -y clang',

            'sudo sysctl -w fs.nr_open=65535',
            'sudo echo "ulimit -n 65535" >> /home/ubuntu/.bashrc',
            'source /home/ubuntu/.bashrc',

            'cd /home/ubuntu',

            # Clone the repo.
            f'(GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git clone {self.settings.repo_url} || (cd {self.settings.repo_name} ; git pull))'
        ]
        try:
            hosts = self.manager.hosts(flat=True)
            g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
            # Copy the Deploy Key to /home/ubuntu
            g.put(self.settings.github_deploy_key_path)
            # Assume the public key has the same name as the private key with '.pub' appended
            g.put(self.settings.github_deploy_key_path + '.pub')
            g.put(".env")
            # Run the installation script
            g.run(' && '.join(cmd), hide=True)
            Print.heading(f'Initialized testbed of {len(hosts)} nodes')
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError('Failed to install repo on testbed', e)

    def run(self, chain_parameters, duration, debug, reuse, dry_run):
        self.initialize(chain_parameters, duration, debug, reuse, dry_run)
        Print.heading('Starting remote run')

        # Compile binary to generate configs
        self._prepare_local_env()

        Print.info('Setting up testbed...')
        hosts = self._select_hosts()
        if not hosts:
            Print.error('Not enough hosts to start the chain remotely')
            return
        self._clear_logs(hosts)
        self._generate_configs(hosts)
        faulty_hosts = self._faulty_hosts(hosts)
        if int(os.environ.get("PASSIVE_OR_CRASHED")) == 1:
            hosts = [host for host in hosts if host not in faulty_hosts]
        try:
            self._start_chain(hosts)

            if not self.dry_run:
                Print.info(f'Running benchmark ({self.duration} sec)...')
                sleep(DEFAULT_DELAY)
                self._start_broadcasting(hosts)
                sleep(self.duration)
                self._stop_broadcasting(hosts)
                sleep(DEFAULT_DELAY)
                self.kill(hosts)
                self.download_log(hosts)
            else:
                Print.info(f'Running benchmark in dry-run mode ...')
        except:
            self._stop_broadcasting(hosts)
            sleep(DEFAULT_DELAY)
            self.kill(hosts)

    def build(self, chain_parameters):
        self.initialize(chain_parameters, duration=0, debug=False, reuse=False, dry_run=False)
        hosts = self._select_hosts()
        if not hosts:
            Print.error('Not enough hosts')
            return
        Print.info('Build release...')
        self._update(hosts)

    def compress_log_file(self, hosts=[]):
        hosts = hosts if hosts else self._select_hosts()
        ips = list(set(hosts))
        args = [(self, ip, self._get_log_file(self._get_identity_file(ip))) for ip in ips]
        with ThreadPool(THREAD_COUNT) as pool:
            pool.starmap(Bench._zip_log, args)
        Print.info('Finish...')

    def download_log(self, hosts=[]):
        hosts = hosts if hosts else self._select_hosts()
        ips = list(set(hosts))
        progress = progress_bar(
            ips, prefix=f'Log count: {len(ips)}'
        )
        self.compress_log_file(hosts)
        args = [(self, ip, self._get_log_file(self._get_identity_file(ip))) for ip in progress]
        with ThreadPool(THREAD_COUNT) as pool:
            pool.starmap(Bench._get_log, args)
        Print.info('Finish...')

    def _get_log(self, ip, log_name):
        local_dir = PathMaker.logs_path()
        src_path = os.path.join(f'/home/ubuntu/{log_name}.tar.gz')
        dest_path = os.path.join(f"{local_dir}/{os.path.basename(log_name)}.tar.gz")
        c = Connection(ip, user='ubuntu', connect_kwargs=self.connect)
        c.get(src_path, local=dest_path)
        Print.info(f"downloaded {log_name}.tar.gz")

    def _zip_log(self, ip, log_name):
        log_path = os.path.join(f'/home/ubuntu/{log_name}')
        c = Connection(ip, user='ubuntu', connect_kwargs=self.connect)
        dir_name = os.path.dirname(log_path)
        file_name = os.path.basename(log_path)
        with c.cd(dir_name):
            c.run(f'tar -zcvf {file_name}.tar.gz {file_name}', hide=True)
        Print.info(f"compressed to {log_path}.tar.gz")

    def stop_nodes(self, chain_parameters):
        self.initialize(chain_parameters, duration=0, debug=False, reuse=False, dry_run=False)
        hosts = self._select_hosts()
        if not hosts:
            Print.error('Not enough hosts')
            return
        Print.info('Stop hosts release...')
        self._stop_broadcasting(hosts)
        self.kill(hosts)

    def kill(self, hosts=[], delete_logs=False):
        assert isinstance(hosts, list)
        assert isinstance(delete_logs, bool)
        hosts = hosts if hosts else self.manager.hosts(flat=True)
        delete_logs = CommandMaker.clean_logs() if delete_logs else 'true'
        cmd = [delete_logs, f'({CommandMaker.kill()} || true)']
        try:
            g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
            g.run(' && '.join(cmd), hide=True)
        except GroupException as e:
            raise BenchError('Failed to kill nodes', FabricError(e))

    def _prepare_local_env(self):
        # Recompile the latest code.
        cmd = CommandMaker.compile().split()
        Print.info(f'Compiling binary {cmd}...')
        subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

        # Create alias for the client and nodes binary.
        cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
        Print.info(f'Alias binary {cmd}...')
        subprocess.run([cmd], shell=True)

    def _select_hosts(self):
        nodes = self.chain_parameters.chain_size()

        # Ensure there are enough hosts.
        hosts = list(set(self.manager.hosts(flat=True)))
        if len(hosts) < nodes:
            return []

        # Select the hosts in different data centers.
        return list(set(hosts[:nodes]))

    def _update(self, hosts):
        if self.dry_run:
            return
        Print.info(
            f'Updating {len(hosts)} machines (branch "{self.settings.branch}")...'
        )
        cmd = [
            f'(cd {self.settings.repo_name} && git fetch -f)',
            f'(cd {self.settings.repo_name} && git checkout -f {self.settings.branch})',
            f'(cd {self.settings.repo_name} && git pull -f)',
            'source $HOME/.cargo/env',
            'export CARGO_NET_GIT_FETCH_WITH_CLI=true',
            f'(cd {self.settings.repo_name}/node && {CommandMaker.compile()})',
            CommandMaker.alias_binaries(
                f'./{self.settings.repo_name}/target/release/'
            )
        ]
        g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
        g.put(".env")
        g.run(' && '.join(cmd), hide=True)
        Print.info("Hosts are updated")

    def _clear_logs(self, hosts):
        # Cleanup all files.
        cmd = [f'{CommandMaker.clean_logs()}']
        if not self.reuse:
            cmd.append(CommandMaker.cleanup())
            cmd.append(CommandMaker.make_dir_cmd(PathMaker.config_dir_path()))
        Print.info(f'Cleaning env locally and remotely: {cmd}...')
        if self.dry_run:
            return
        subprocess.run([";".join(cmd)], shell=True, stderr=subprocess.DEVNULL)
        sleep(0.5)  # Removing the store may take time.
        g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
        g.run(' && '.join(cmd), hide=True)

    def _generate_configs(self, hosts):
        if self.reuse:
            return
        chain_config = PathMaker.chain_parameters_file()
        nt_config = PathMaker.network_config_file()
        ips_config = PathMaker.host_ips_file()
        output = PathMaker.config_dir_path()
        fault_percent = os.environ.get("FAULT_PERCENT")
        CommandMaker.make_dir(output)
        self.chain_parameters.print(chain_config)
        self.chain_parameters.print_network_config(nt_config)
        dump_json(ips_config, hosts)
        cmd = CommandMaker.generate_key(nt_config, output, fault_percent, ips_config)
        Print.info(f'Generating configs {cmd}...')
        try:
            subprocess.check_output(cmd, shell=True)
            sleep(0.5)  # Generation may take some time
        except subprocess.SubprocessError as e:
            raise BenchError('Failed to generate configs', e)

    def _faulty_hosts(self, hosts):
        faulty = [Path(f).stem for f in FaultyNodeIdentifier.load(PathMaker.chain_faulty_peers_file()).faulty_identy]
        return [
            host
            for host in hosts
            if
            '_'.join(Path(Bench._get_identity_file(host)).stem.split('_')[0:-1]) in faulty
        ]

    def _start_chain(self, hosts):
        upload_args = [(self, host) for host in hosts]
        run_background_args = [(self, host,
                                CommandMaker.run_node(PathMaker.chain_parameters_file(),
                                                      Bench._get_identity_file(host),
                                                      PathMaker.chain_peers_file(), self.debug),
                                Bench._get_log_file(Bench._get_identity_file(host)))
                               for host in hosts]
        with ThreadPool(THREAD_COUNT) as pool:
            result = pool.starmap(Bench._upload_config, upload_args)
            print(result)

        with ThreadPool(THREAD_COUNT) as pool:
            pool.starmap(Bench._background_run, run_background_args)

    def _upload_config(self, host):
        if self.dry_run:
            return Bench._get_identity_file(host)
        config_destination = f'{PathMaker.config_dir_path()}'
        c = Connection(host, user='ubuntu', connect_kwargs=self.connect)
        c.run(f'{CommandMaker.cleanup()} || true', hide=True)
        c.run(f'{CommandMaker.make_dir_cmd(PathMaker.config_dir_path())} || true', hide=True)
        c.put(PathMaker.chain_parameters_file(), config_destination)
        c.put(PathMaker.chain_peers_file(), config_destination)
        c.put(PathMaker.chain_faulty_peers_file(), config_destination)
        identity_file = Bench._get_identity_file(host)
        c.put(identity_file, config_destination)
        return identity_file

    def _background_run(self, host, command, log_file):
        Print.info(f'Starting node on host: {host} - {command} - {log_file}')
        if self.dry_run:
            return
        name = "_".join(splitext(basename(log_file))[0].split('_')[:-1])
        cmd = f'tmux new -d -s "{name}" "{command} |& tee {log_file}"'
        c = Connection(host, user='ubuntu', connect_kwargs=self.connect)
        c.put(".env")
        output = c.run(cmd, hide=True)
        Bench._check_stderr(output)

    @staticmethod
    def _get_identity_file(host):
        identity_file_pattern = os.path.join(PathMaker.config_dir_path(), f'*_{host}.json')
        files = glob.glob(identity_file_pattern)
        if not files:
            raise BenchError(f'failed to locate identity file for host: {host}')
        return files[0]

    @staticmethod
    def _get_log_file(identity_file):
        file_name = os.path.splitext(os.path.basename(identity_file))[0]
        log_file_name = file_name.replace("node", "log")
        return os.path.join(PathMaker.logs_path(), ".".join([log_file_name, "log"]))

    def _start_broadcasting(self, hosts):
        Print.info("creating .chain_ready file")
        cmd = f"touch .chain_ready"
        g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
        g.run(cmd, hide=True)
        Print.info("hosts are updated with .chain_ready file")

    def _stop_broadcasting(self, hosts):
        Print.info("removing .chain_ready file")
        cmd = f"rm -f .chain_ready"
        g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
        g.run(cmd, hide=True)
        Print.info("hosts are updated with no .chain_ready file")

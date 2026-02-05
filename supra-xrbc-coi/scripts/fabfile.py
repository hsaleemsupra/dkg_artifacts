import os
from dotenv import load_dotenv
from fabric import task
from utilities.config import ChainParameters
from utilities.instance import InstanceManager
from utilities.local import LocalRunner
from utilities.remote import Bench
from utilities.utils import Print
from utilities.utils import BenchError

print(f"Loading environment variables {load_dotenv('.env')}")

@task
def local(ctx, chain_parameters=os.environ.get("CHAIN_PARAMETER"), duration=int(os.environ.get("DURATION")), reuse=False, dry_run=False, debug=False):
    """ Run chain on localhost """
    try:
        ret = LocalRunner(chain_parameters, reuse, dry_run, duration=duration, debug=debug).run()
    except BenchError as e:
        Print.error(e)

@task
def create(ctx, chain_parameters=os.environ.get("CHAIN_PARAMETER")):
    ''' Create a testbed'''
    chain_size = ChainParameters.load(chain_parameters).chain_size()
    try:
        InstanceManager.make().create_instances(chain_size)
    except BenchError as e:
        Print.error(e)

@task
def reset(ctx, chain_parameters=os.environ.get("CHAIN_PARAMETER")):
    ''' reset instance key'''
    try:
        InstanceManager.make().delete_keypair()
        InstanceManager.make().create_keypair()
    except BenchError as e:
        Print.error(e)

@task
def destroy(ctx):
    ''' Destroy the testbed '''
    try:
        InstanceManager.make().terminate_instances()
    except BenchError as e:
        Print.error(e)

@task
def install(ctx):
    ''' Install the codebase on all machines '''
    try:
        Bench(ctx).install()
    except BenchError as e:
        Print.error(e)

@task
def start(ctx, chain_parameters=os.environ.get("CHAIN_PARAMETER")):
    ''' Start at most `max` machines per data center '''
    chain_size = ChainParameters.load(chain_parameters).chain_size()
    try:
        InstanceManager.make().start_instances(chain_size)
    except BenchError as e:
        Print.error(e)
@task
def stop_nodes(ctx, chain_parameters=os.environ.get("CHAIN_PARAMETER")):
    ''' Stop nodes on remote instances '''
    try:
        Bench(ctx).stop_nodes(chain_parameters)
    except BenchError as e:
        Print.error(e)

@task
def stop(ctx):
    ''' Stop all machines '''
    try:
        InstanceManager.make().stop_instances()
    except BenchError as e:
        Print.error(e)

@task
def info(ctx):
    ''' Display connect information about all the available machines '''
    try:
        InstanceManager.make().print_info()
    except BenchError as e:
        Print.error(e)

@task
def remote(ctx, chain_parameters=os.environ.get("CHAIN_PARAMETER"), duration=int(os.environ.get("DURATION")), reuse=False, dry_run=False, debug=False):
    ''' Run benchmarks on AWS '''
    try:
        Bench(ctx).run(chain_parameters, duration, debug, reuse, dry_run)
    except BenchError as e:
        Print.error(e)

@task
def build(ctx, chain_parameters=os.environ.get("CHAIN_PARAMETER")):
    ''' Build source on AWS '''
    try:
        Bench(ctx).build(chain_parameters)
    except BenchError as e:
        Print.error(e)

@task
def log(ctx, chain_parameters=os.environ.get("CHAIN_PARAMETER")):
    ''' Download Logs '''
    try:
        bench = Bench(ctx)
        bench.initialize(chain_parameters, 0, False, False, False)
        bench.download_log([])
    except BenchError as e:
        Print.error(e)

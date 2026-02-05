use crate::chain_parameters::ChainParameters;
use crate::cli::{NodeCli, NodeSubCommand};
use crate::generator::Generator;
use crate::runner::NodeRunner;
use clap::Parser;
use env_logger::Target;
use log::{info, LevelFilter};

mod chain_parameters;
mod cli;
mod generator;
mod helpers;
mod runner;

#[tokio::main]
async fn main() {
    let cli_arguments: NodeCli = NodeCli::parse();
    init_logger(&cli_arguments);
    match cli_arguments.command {
        NodeSubCommand::Run(run_args) => {
            info!("Starting Node");
            let handle = NodeRunner::start(run_args).await;
            let _ = handle.await;
        }
        NodeSubCommand::Dump => {
            ChainParameters::dump_default_config().expect("Successful dump of chain parameters");
        }
        NodeSubCommand::Generate(args) => Generator::run(args),
    }
}

fn init_logger(cli_arguments: &NodeCli) {
    let mut env_log_builder = env_logger::builder();
    let log_level = match cli_arguments.verbose {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    println!("Enabling {} logging level", log_level);
    env_log_builder
        .filter_level(log_level)
        .target(Target::Stdout)
        .format_timestamp_millis()
        .init();
}

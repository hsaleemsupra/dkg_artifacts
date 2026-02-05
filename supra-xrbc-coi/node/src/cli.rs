use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
pub struct NodeCli {
    #[command(subcommand)]
    pub command: NodeSubCommand,

    #[clap(
        short,
        long,
        help = "Level of verbosity, the higher the number of \"v\"s the higher the level"
    )]
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand)]
pub enum NodeSubCommand {
    #[clap(about = "Starts node with the input configurations")]
    Run(RunArgs),
    #[clap(about = "Dumps default chain parameters to file")]
    Dump,
    #[clap(
        about = "Generates and dumps random topology in terms of peers details and node \
                 identities based on the input network configuration"
    )]
    Generate(GeneratorArgs),
}

#[derive(Args)]
pub struct PathArg {
    #[clap(help = "Full path to configuration file")]
    pub value: PathBuf,
}

#[derive(Args)]
pub struct RunArgs {
    #[clap(help = "Full path to chain configuration parameters file")]
    pub chain_param_file: PathBuf,
    #[clap(help = "Full path to node identity config")]
    pub identity_config: PathBuf,
    #[clap(help = "Full path to peers detailed config")]
    pub peers_config: PathBuf,
}

#[derive(Args)]
pub struct GeneratorArgs {
    #[clap(help = "Full path to network configuration parameters file")]
    pub network_config_file: PathBuf,
    #[clap(help = "Full path to destination directory")]
    pub destination: PathBuf,
    #[clap(help = "Percentage of faulty node present in experiment chain")]
    pub fault_percent: usize,
    #[clap(help = "Full path to remote ip addresses if configs are for remote run")]
    pub remote_ips: Option<PathBuf>,
}

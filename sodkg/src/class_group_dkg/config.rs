#[derive(Debug, Clone)]
// Shouldn't common provide means to validate configuration parameters ?
pub struct DkgConfig {
    // if the dkg is for the whole tribe, threshold = 2f+1
    // if the dkg is for a clan only, threshold = f+1
    pub threshold: u32,
    // total nodes in the committee
    // total_nodes >= 3f+1 if the dkg is for the whole tribe
    // total_nodes >= 2f+1 if the dkg is just for the clan
    pub total_nodes: u32,
    // threshold_clan = f+1
    pub threshold_clan: u32,
    // total nodes in the dkg clan
    // All nodes in the dkg clan act as dealers during the dkg process
    // typically total_nodes_clan = 2f+1
    pub total_nodes_clan: u32,
    // the dealer, after sending their dealings, would wait for this time duration to collect >= threshold
    // signatures on their dealing. Once collected sigs >= threshold and timer has expired, the dealer proceeds to
    // next step
    pub dealing_sig_collection_timeout_ms: u64,

}

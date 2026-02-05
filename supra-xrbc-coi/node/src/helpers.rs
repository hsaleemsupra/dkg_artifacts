use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::{write, File};
use std::io::{Error, Read};
use std::path::PathBuf;

///
/// Loads file content to in memory
///
pub fn load_file(config_file_path: PathBuf) -> Result<String, Error> {
    let mut content: String = String::new();
    File::open(config_file_path)?.read_to_string(&mut content)?;
    Ok(content)
}

///
/// Deserializes an object from json string
///
pub fn from_json_string<'a, T: Deserialize<'a>>(raw_data: &'a str) -> Result<T, Error> {
    serde_json::from_str::<T>(raw_data).map_err(Error::from)
}

///
/// Loads object from file
///
pub fn load<T: DeserializeOwned>(file_path: PathBuf) -> Result<T, Error> {
    let content = load_file(file_path)?;
    from_json_string::<T>(&content)
}

///
/// Dumps object into file in pretty json format
///
pub fn dump<T: Serialize>(data: &T, config_file_path: PathBuf) -> Result<(), Error> {
    let config = serde_json::to_string_pretty(data)?;
    write(config_file_path.as_path(), config)
}

#[test]
fn test_load_file() {
    let valid_case = load_file(PathBuf::from("src/resources/valid_config.json"));
    assert!(valid_case.is_ok());
    assert!(!valid_case.unwrap().is_empty());

    let invalid_case = load_file(PathBuf::from("unknown_file.txt"));
    assert!(invalid_case.is_err());
}

#[test]
fn test_load() {
    use crate::chain_parameters::ChainParameters;
    use network::topology::config::NetworkConfig;

    let valid_case = load::<ChainParameters>(PathBuf::from("src/resources/valid_config.json"));
    assert!(valid_case.is_ok());

    let invalid_case = load::<ChainParameters>(PathBuf::from("unknown_file.txt"));
    assert!(invalid_case.is_err());

    let invalid_case_data = load::<NetworkConfig>(PathBuf::from("src/resources/valid_config.json"));
    assert!(invalid_case_data.is_err());
}

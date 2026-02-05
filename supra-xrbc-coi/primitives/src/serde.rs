use crate::error::CommonError;
use bincode::{DefaultOptions, Options};
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};

pub fn bincode_serializer<Data: Serialize>(data: &Data) -> Result<Bytes, CommonError> {
    bincode::serialize(data)
        .map_err(CommonError::SerdeError)
        .map(Bytes::from)
}

pub fn bincode_deserialize<'de, Data: Deserialize<'de>>(
    bytes: &'de [u8],
) -> Result<Data, CommonError> {
    bincode::deserialize::<Data>(bytes).map_err(CommonError::SerdeError)
}

pub trait DeserializerCustom {
    fn deserialize_wrapper<'de, D: Deserializer<'de>>(d: D) -> Result<Self, D::Error>
    where
        Self: Sized;
}

pub fn bincode_deserialize_custom<Data: DeserializerCustom>(
    bytes: &[u8],
) -> Result<Data, CommonError> {
    let options = DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes();
    let mut des = bincode::Deserializer::from_slice(bytes, options);
    Data::deserialize_wrapper(&mut des).map_err(CommonError::SerdeError)
}

#[cfg(test)]
mod tests {
    use crate::serde::{
        bincode_deserialize, bincode_deserialize_custom, bincode_serializer, DeserializerCustom,
    };
    use serde::{Deserialize, Deserializer, Serialize};
    use std::collections::HashMap;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestCustomData {
        p_int: u16,
        p_vec: Vec<u8>,
        p_map: HashMap<u16, u32>,
    }

    impl TestCustomData {
        fn random() -> Self {
            TestCustomData {
                p_int: 458,
                p_vec: vec![5; 69],
                p_map: HashMap::from([(2, 32), (4, 56), (7, 74)]),
            }
        }
    }
    impl DeserializerCustom for TestCustomData {
        fn deserialize_wrapper<'de, D: Deserializer<'de>>(d: D) -> Result<Self, D::Error>
        where
            Self: Sized,
        {
            <TestCustomData as Deserialize>::deserialize(d)
        }
    }

    #[test]
    fn check_serde_utilities() {
        let data = TestCustomData::random();
        let bytes = bincode_serializer(&data).expect("Serialized byte array");

        let deserialized_data =
            bincode_deserialize::<TestCustomData>(&bytes).expect("Deserialized data");

        let deserialized_data_custom_ifc =
            bincode_deserialize_custom::<TestCustomData>(&bytes).expect("Valid deserialized data");
        assert_eq!(deserialized_data, data);
        assert_eq!(deserialized_data, deserialized_data_custom_ifc);
    }
}

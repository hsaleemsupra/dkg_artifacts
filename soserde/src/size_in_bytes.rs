pub trait SizeInBytes {
    fn size_in_bytes(&self) -> usize;
}

/// Defines [SizeInBytes] trait for specified struct.
///
/// If custom body has been provided as block expression then it will be used as trait function
/// definition body,otherwise default implementation will be generated, which will convert the struct
/// instance to bytes and return the length.
///
/// Note that default implementation will require that specified struct is serializable,
/// which will lead automatically to have [crate::SmrSerialize] implemented for it,
/// as default implementation will use [crate::SmrSerialize::to_bytes] to convert the object to bytes.
///
/// #Example
/// ```
/// use serde::{Deserialize, Serialize};
/// use soserde::{impl_size_in_bytes, SizeInBytes};;
///
/// struct U8Wrapper (u8);
/// impl_size_in_bytes!(U8Wrapper, self { size_of_val(&self.0) });
///
/// #[derive(Serialize, Deserialize)]
/// struct VectorWrapper(Vec<u8>);
/// impl_size_in_bytes!(VectorWrapper);
/// ```
#[macro_export]
macro_rules! impl_size_in_bytes {
    ($struct_name:ident, $sel:ident $custom_body:block) => {
        impl $crate::SizeInBytes for $struct_name {
            fn size_in_bytes(&$sel) -> usize $custom_body
        }
    };
    ($struct_name:ident) => {
        impl $crate::SizeInBytes for $struct_name {
            fn size_in_bytes(&self) -> usize {
                use $crate::SmrSerialize;
                Self::to_bytes(self).len()
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{impl_size_in_bytes, SizeInBytes};
    use serde::{Deserialize, Serialize};

    struct U8Wrapper(u8);
    impl_size_in_bytes!(U8Wrapper, self { size_of_val(&self.0) });

    #[derive(Serialize, Deserialize)]
    struct VectorU8Wrapper(Vec<u8>);
    impl_size_in_bytes!(VectorU8Wrapper);

    #[derive(Serialize, Deserialize)]
    struct VectorU16Wrapper(Vec<u16>);
    impl_size_in_bytes!(VectorU16Wrapper);
    #[test]
    fn check_macro_definition() {
        let u8_wrapper = U8Wrapper(15);
        let vec_u8_wrapper = VectorU8Wrapper(vec![45; 320]);
        assert_eq!(u8_wrapper.size_in_bytes(), 1);
        assert_eq!(
            vec_u8_wrapper.size_in_bytes(),
            // when serialized length of the size also serialized and used only enough bytes to enclose the actual vector length.
            vec_u8_wrapper.0.len() + 2
        );
        let vec_u16_wrapper = VectorU16Wrapper(vec![45; 42]);
        assert_eq!(
            vec_u16_wrapper.size_in_bytes(),
            // when serialized length of the size also serialized and used only enough bytes to enclose the actual vector length.
            2 * vec_u16_wrapper.0.len() + 1
        );
    }
}

use super::ecp2_wrapper::Ecp2Wrapper;
use super::ecp_wrapper::EcpWrapper;
use crate::types::serde::TRawRepresentation;
use crate::types::CryptoResult;
use crypto::bls12381::bls12381_serde::{ECP2_SIZE, ECP_SIZE};
use miracl_core_bls12381::bls12381::big::MODBYTES;
use miracl_core_bls12381::bls12381::{big::BIG, ecp::ECP, ecp2::ECP2};

pub(crate) const BIG_RAW_SIZE: usize = MODBYTES;
impl TRawRepresentation for BIG {
    type Raw = [u8; BIG_RAW_SIZE];

    fn create() -> Self::Raw {
        [0u8; BIG_RAW_SIZE]
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        Ok(BIG::frombytes(&src))
    }

    fn to_raw(&self) -> Self::Raw {
        let mut raw_signature = Self::create();
        self.tobytes(&mut raw_signature);
        raw_signature
    }
}

pub(crate) const ECP_RAW_SIZE: usize = ECP_SIZE + 1;
impl TRawRepresentation for ECP {
    type Raw = [u8; ECP_RAW_SIZE];

    fn create() -> Self::Raw {
        [0u8; ECP_RAW_SIZE]
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        Ok(ECP::frombytes(&src))
    }

    fn to_raw(&self) -> Self::Raw {
        let mut raw_signature = Self::create();
        self.tobytes(&mut raw_signature, true);
        raw_signature
    }
}

impl TRawRepresentation for EcpWrapper {
    type Raw = <ECP as TRawRepresentation>::Raw;

    fn create() -> Self::Raw {
        <ECP as TRawRepresentation>::create()
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        <ECP as TRawRepresentation>::from_raw(src).map(EcpWrapper)
    }

    fn to_raw(&self) -> Self::Raw {
        self.0.to_raw()
    }
}

pub(crate) const ECP2_RAW_SIZE: usize = ECP2_SIZE + 1;
impl TRawRepresentation for ECP2 {
    type Raw = [u8; ECP2_RAW_SIZE];

    fn create() -> Self::Raw {
        [0u8; ECP2_RAW_SIZE]
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        Ok(ECP2::frombytes(&src))
    }

    fn to_raw(&self) -> Self::Raw {
        let mut raw_signature = Self::create();
        self.tobytes(&mut raw_signature, true);
        raw_signature
    }
}

impl TRawRepresentation for Ecp2Wrapper {
    type Raw = <ECP2 as TRawRepresentation>::Raw;

    fn create() -> Self::Raw {
        <ECP2 as TRawRepresentation>::create()
    }
    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        <ECP2 as TRawRepresentation>::from_raw(src).map(Ecp2Wrapper)
    }

    fn to_raw(&self) -> Self::Raw {
        self.0.to_raw()
    }
}

#[cfg(test)]
mod tests {
    use crate::types::impls::helpers::rand::rng_from_seed;
    use crate::types::serde::TRawRepresentation;
    use miracl_core_bls12381::bls12381::big::BIG;
    use miracl_core_bls12381::bls12381::ecp::ECP;
    use miracl_core_bls12381::bls12381::ecp2::ECP2;

    #[test]
    fn check_big_raw_representation() {
        let big = BIG::random(&mut rng_from_seed());
        let raw_big = big.to_raw();
        let _from_raw_big = BIG::from_raw(raw_big).expect("BIG successful recovery from raw bytes");
    }
    #[test]
    fn check_ecp_raw_representation() {
        let ecp = ECP::generator();
        let raw_ecp = ecp.to_raw();
        let from_raw_ecp = ECP::from_raw(raw_ecp).expect("ECP successful recovery from raw bytes");
        assert!(ecp.equals(&from_raw_ecp));
    }

    #[test]
    fn check_ecp2_raw_representation() {
        let ecp2 = ECP2::generator();
        let raw_ecp2 = ecp2.to_raw();
        let from_raw_ecp2 =
            ECP2::from_raw(raw_ecp2).expect("ECP2 successful recovery from raw bytes");
        assert!(ecp2.equals(&from_raw_ecp2));
    }
}

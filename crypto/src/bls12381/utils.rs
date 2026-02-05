use std::ops::{Deref};
use blsttc::Fr;
use cpp_std::VectorOfUchar;
use bicycl::b_i_c_y_c_l::{CLHSMqk, Mpz};
use bicycl::{cpp_vec_to_rust, rust_vec_to_cpp};
use bicycl::cl_config::get_cl_bls12381;

pub fn get_cl() -> cpp_core::CppBox<CLHSMqk> {
    get_cl_bls12381()
}

pub unsafe fn fr_to_mpz(a: Fr) -> cpp_core::CppBox<Mpz> {
    let buffer = a.to_bytes_be().to_vec();
    let buffer_cpp = rust_vec_to_cpp(buffer.clone());
    let ref_buffer: cpp_core::Ref<VectorOfUchar> = unsafe {
        cpp_core::Ref::from_raw_ref(&buffer_cpp)
    };
    let mut result = Mpz::new();
    result.b_i_g_bytes_to_mpz(ref_buffer);
    result
}

pub unsafe fn mpz_to_fr(a: &mut Mpz) -> Fr {
    let big_bytes = a.mpz_to_b_i_g_bytes();
    let buff = cpp_vec_to_rust(big_bytes.deref());
    let mut buff_ext = Vec::new();
    let appended_zeroes;
    if buff.len()>=32 {
        appended_zeroes = 0;
    }
    else {
        appended_zeroes = 32-buff.len();
    }

    for _i in 0..(appended_zeroes){
        buff_ext.push(0);
    }

    for i in 0.. buff.len(){
        buff_ext.push(buff[i]);
    }
    Fr::from_bytes_be(&buff_ext.try_into().expect("failed to convert")).expect("failed to convert")
}

#[cfg(test)]
mod test {
    use blsttc::{group::ff::Field, Fr};
    use rand::{thread_rng};
    use super::{fr_to_mpz, mpz_to_fr};
    use std::ops::{DerefMut};

    #[test]
    fn test_convert_and_return_fr() {
        let mut rng = thread_rng();
        for _ in 0..100 {

            unsafe {
                let fr_expected = Fr::random(&mut rng);
                let mut mpz_fr = fr_to_mpz(fr_expected);
                let fr_regen = mpz_to_fr(mpz_fr.deref_mut());

                assert_eq!(fr_expected, fr_regen);
            }
        }
    }
}
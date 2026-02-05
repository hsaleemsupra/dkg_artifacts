use crate::b_i_c_y_c_l::{ClassGroup, CLHSMqk, Mpz, QFI};
use crate::constants::{CL_DELTA_DISC_VEC_BLS12381, CL_DELTA_DISC_VEC_BN254, CL_DELTA_K_DISC_VEC_BLS12381, CL_DELTA_K_DISC_VEC_BN254, D, E, EXP_BOUND_VEC_BLS12381, EXP_BOUND_VEC_BN254, H_A_VEC_BLS12381, H_A_VEC_BN254, H_B_VEC_BLS12381, H_B_VEC_BN254, H_C_VEC_BLS12381, H_C_VEC_BN254, H_D_PRECOMP_A_VEC_BLS12381, H_D_PRECOMP_A_VEC_BN254, H_D_PRECOMP_B_VEC_BLS12381, H_D_PRECOMP_B_VEC_BN254, H_D_PRECOMP_C_VEC_BLS12381, H_D_PRECOMP_C_VEC_BN254, H_DE_PRECOMP_A_VEC_BLS12381, H_DE_PRECOMP_A_VEC_BN254, H_DE_PRECOMP_B_VEC_BLS12381, H_DE_PRECOMP_B_VEC_BN254, H_DE_PRECOMP_C_VEC_BLS12381, H_DE_PRECOMP_C_VEC_BN254, H_E_PRECOMP_A_VEC_BLS12381, H_E_PRECOMP_A_VEC_BN254, H_E_PRECOMP_B_VEC_BLS12381, H_E_PRECOMP_B_VEC_BN254, H_E_PRECOMP_C_VEC_BLS12381, H_E_PRECOMP_C_VEC_BN254, K, P_VEC_BLS12381, P_VEC_BN254, Q_VEC_BLS12381, Q_VEC_BN254};
use crate::rust_vec_to_mpz;

pub fn get_cl_bls12381() -> cpp_core::CppBox<CLHSMqk>{
    let p_mpz = unsafe{rust_vec_to_mpz(P_VEC_BLS12381.to_vec())};
    let ref_p_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &p_mpz)};
    let q_mpz = unsafe{rust_vec_to_mpz(Q_VEC_BLS12381.to_vec())};
    let ref_q_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &q_mpz)};

    let cl_delta_k_disc_mpz = unsafe{rust_vec_to_mpz(CL_DELTA_K_DISC_VEC_BLS12381.to_vec())};
    let ref_cl_delta_k_disc_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&cl_delta_k_disc_mpz )};
    let cl_delta_k_disc = unsafe{ClassGroup::new(ref_cl_delta_k_disc_mpz)};
    let ref_cl_delta_k_disc: cpp_core::Ref<ClassGroup> = unsafe{cpp_core::Ref::from_raw_ref( &cl_delta_k_disc)};

    let cl_delta_disc_mpz = unsafe{rust_vec_to_mpz(CL_DELTA_DISC_VEC_BLS12381.to_vec())};
    let ref_cl_delta_disc_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&cl_delta_disc_mpz )};
    let cl_delta_disc = unsafe{ClassGroup::new(ref_cl_delta_disc_mpz)};
    let ref_cl_delta_disc: cpp_core::Ref<ClassGroup> = unsafe{cpp_core::Ref::from_raw_ref( &cl_delta_disc)};

    let h_a_mpz = unsafe{rust_vec_to_mpz(H_A_VEC_BLS12381.to_vec())};
    let h_b_mpz = unsafe{rust_vec_to_mpz(H_B_VEC_BLS12381.to_vec())};
    let h_c_mpz = unsafe{rust_vec_to_mpz(H_C_VEC_BLS12381.to_vec())};

    let ref_h_a_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_a_mpz)};
    let ref_h_b_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_b_mpz)};
    let ref_h_c_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_c_mpz)};

    let h = unsafe{QFI::new_3a(ref_h_a_mpz, ref_h_b_mpz, ref_h_c_mpz)};
    let ref_h : cpp_core::Ref<QFI> = unsafe{cpp_core::Ref::from_raw_ref( &h)};

    let exp_bound = unsafe{rust_vec_to_mpz(EXP_BOUND_VEC_BLS12381.to_vec())};
    let ref_exp_bound_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &exp_bound)};

    let h_e_precomp_a_mpz = unsafe{rust_vec_to_mpz(H_E_PRECOMP_A_VEC_BLS12381.to_vec())};
    let h_e_precomp_b_mpz = unsafe{rust_vec_to_mpz(H_E_PRECOMP_B_VEC_BLS12381.to_vec())};
    let h_e_precomp_c_mpz = unsafe{rust_vec_to_mpz(H_E_PRECOMP_C_VEC_BLS12381.to_vec())};

    let ref_h_e_precomp_a_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_e_precomp_a_mpz)};
    let ref_h_e_precomp_b_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_e_precomp_b_mpz)};
    let ref_h_e_precomp_c_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_e_precomp_c_mpz)};

    let h_e_precomp = unsafe{QFI::new_3a(ref_h_e_precomp_a_mpz, ref_h_e_precomp_b_mpz, ref_h_e_precomp_c_mpz)};
    let ref_h_e_precomp : cpp_core::Ref<QFI> = unsafe{cpp_core::Ref::from_raw_ref( &h_e_precomp)};

    let h_d_precomp_a_mpz = unsafe{rust_vec_to_mpz(H_D_PRECOMP_A_VEC_BLS12381.to_vec())};
    let h_d_precomp_b_mpz = unsafe{rust_vec_to_mpz(H_D_PRECOMP_B_VEC_BLS12381.to_vec())};
    let h_d_precomp_c_mpz = unsafe{rust_vec_to_mpz(H_D_PRECOMP_C_VEC_BLS12381.to_vec())};

    let ref_h_d_precomp_a_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_d_precomp_a_mpz)};
    let ref_h_d_precomp_b_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_d_precomp_b_mpz)};
    let ref_h_d_precomp_c_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_d_precomp_c_mpz)};

    let h_d_precomp = unsafe{QFI::new_3a(ref_h_d_precomp_a_mpz, ref_h_d_precomp_b_mpz, ref_h_d_precomp_c_mpz)};
    let ref_h_d_precomp : cpp_core::Ref<QFI> = unsafe{cpp_core::Ref::from_raw_ref( &h_d_precomp)};

    let h_de_precomp_a_mpz = unsafe{rust_vec_to_mpz(H_DE_PRECOMP_A_VEC_BLS12381.to_vec())};
    let h_de_precomp_b_mpz = unsafe{rust_vec_to_mpz(H_DE_PRECOMP_B_VEC_BLS12381.to_vec())};
    let h_de_precomp_c_mpz = unsafe{rust_vec_to_mpz(H_DE_PRECOMP_C_VEC_BLS12381.to_vec())};

    let ref_h_de_precomp_a_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_de_precomp_a_mpz)};
    let ref_h_de_precomp_b_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_de_precomp_b_mpz)};
    let ref_h_de_precomp_c_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_de_precomp_c_mpz)};

    let h_de_precomp = unsafe{QFI::new_3a(ref_h_de_precomp_a_mpz, ref_h_de_precomp_b_mpz, ref_h_de_precomp_c_mpz)};
    let ref_h_de_precomp : cpp_core::Ref<QFI> = unsafe{cpp_core::Ref::from_raw_ref( &h_de_precomp)};

    let c = unsafe{ CLHSMqk::from_c_l_h_s_mqk_all(ref_q_mpz, K, ref_p_mpz, false, false,
                                                  ref_q_mpz, ref_cl_delta_k_disc, ref_cl_delta_disc, ref_exp_bound_mpz, ref_h, ref_h_e_precomp, ref_h_d_precomp,
                                                  ref_h_de_precomp, D, E)};
    c
}

pub fn get_cl_bn254() -> cpp_core::CppBox<CLHSMqk>{
    let p_mpz = unsafe{rust_vec_to_mpz(P_VEC_BN254.to_vec())};
    let ref_p_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &p_mpz)};
    let q_mpz = unsafe{rust_vec_to_mpz(Q_VEC_BN254.to_vec())};
    let ref_q_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &q_mpz)};

    let cl_delta_k_disc_mpz = unsafe{rust_vec_to_mpz(CL_DELTA_K_DISC_VEC_BN254.to_vec())};
    let ref_cl_delta_k_disc_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&cl_delta_k_disc_mpz )};
    let cl_delta_k_disc = unsafe{ClassGroup::new(ref_cl_delta_k_disc_mpz)};
    let ref_cl_delta_k_disc: cpp_core::Ref<ClassGroup> = unsafe{cpp_core::Ref::from_raw_ref( &cl_delta_k_disc)};

    let cl_delta_disc_mpz = unsafe{rust_vec_to_mpz(CL_DELTA_DISC_VEC_BN254.to_vec())};
    let ref_cl_delta_disc_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&cl_delta_disc_mpz )};
    let cl_delta_disc = unsafe{ClassGroup::new(ref_cl_delta_disc_mpz)};
    let ref_cl_delta_disc: cpp_core::Ref<ClassGroup> = unsafe{cpp_core::Ref::from_raw_ref( &cl_delta_disc)};

    let h_a_mpz = unsafe{rust_vec_to_mpz(H_A_VEC_BN254.to_vec())};
    let h_b_mpz = unsafe{rust_vec_to_mpz(H_B_VEC_BN254.to_vec())};
    let h_c_mpz = unsafe{rust_vec_to_mpz(H_C_VEC_BN254.to_vec())};

    let ref_h_a_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_a_mpz)};
    let ref_h_b_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_b_mpz)};
    let ref_h_c_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_c_mpz)};

    let h = unsafe{QFI::new_3a(ref_h_a_mpz, ref_h_b_mpz, ref_h_c_mpz)};
    let ref_h : cpp_core::Ref<QFI> = unsafe{cpp_core::Ref::from_raw_ref( &h)};

    let exp_bound = unsafe{rust_vec_to_mpz(EXP_BOUND_VEC_BN254.to_vec())};
    let ref_exp_bound_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &exp_bound)};

    let h_e_precomp_a_mpz = unsafe{rust_vec_to_mpz(H_E_PRECOMP_A_VEC_BN254.to_vec())};
    let h_e_precomp_b_mpz = unsafe{rust_vec_to_mpz(H_E_PRECOMP_B_VEC_BN254.to_vec())};
    let h_e_precomp_c_mpz = unsafe{rust_vec_to_mpz(H_E_PRECOMP_C_VEC_BN254.to_vec())};

    let ref_h_e_precomp_a_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_e_precomp_a_mpz)};
    let ref_h_e_precomp_b_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_e_precomp_b_mpz)};
    let ref_h_e_precomp_c_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_e_precomp_c_mpz)};

    let h_e_precomp = unsafe{QFI::new_3a(ref_h_e_precomp_a_mpz, ref_h_e_precomp_b_mpz, ref_h_e_precomp_c_mpz)};
    let ref_h_e_precomp : cpp_core::Ref<QFI> = unsafe{cpp_core::Ref::from_raw_ref( &h_e_precomp)};

    let h_d_precomp_a_mpz = unsafe{rust_vec_to_mpz(H_D_PRECOMP_A_VEC_BN254.to_vec())};
    let h_d_precomp_b_mpz = unsafe{rust_vec_to_mpz(H_D_PRECOMP_B_VEC_BN254.to_vec())};
    let h_d_precomp_c_mpz = unsafe{rust_vec_to_mpz(H_D_PRECOMP_C_VEC_BN254.to_vec())};

    let ref_h_d_precomp_a_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_d_precomp_a_mpz)};
    let ref_h_d_precomp_b_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_d_precomp_b_mpz)};
    let ref_h_d_precomp_c_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_d_precomp_c_mpz)};

    let h_d_precomp = unsafe{QFI::new_3a(ref_h_d_precomp_a_mpz, ref_h_d_precomp_b_mpz, ref_h_d_precomp_c_mpz)};
    let ref_h_d_precomp : cpp_core::Ref<QFI> = unsafe{cpp_core::Ref::from_raw_ref( &h_d_precomp)};

    let h_de_precomp_a_mpz = unsafe{rust_vec_to_mpz(H_DE_PRECOMP_A_VEC_BN254.to_vec())};
    let h_de_precomp_b_mpz = unsafe{rust_vec_to_mpz(H_DE_PRECOMP_B_VEC_BN254.to_vec())};
    let h_de_precomp_c_mpz = unsafe{rust_vec_to_mpz(H_DE_PRECOMP_C_VEC_BN254.to_vec())};

    let ref_h_de_precomp_a_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_de_precomp_a_mpz)};
    let ref_h_de_precomp_b_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_de_precomp_b_mpz)};
    let ref_h_de_precomp_c_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref( &h_de_precomp_c_mpz)};

    let h_de_precomp = unsafe{QFI::new_3a(ref_h_de_precomp_a_mpz, ref_h_de_precomp_b_mpz, ref_h_de_precomp_c_mpz)};
    let ref_h_de_precomp : cpp_core::Ref<QFI> = unsafe{cpp_core::Ref::from_raw_ref( &h_de_precomp)};

    let c = unsafe{ CLHSMqk::from_c_l_h_s_mqk_all(ref_q_mpz, K, ref_p_mpz, false, false,
                                                  ref_q_mpz, ref_cl_delta_k_disc, ref_cl_delta_disc, ref_exp_bound_mpz, ref_h, ref_h_e_precomp, ref_h_d_precomp,
                                                  ref_h_de_precomp, D, E)};
    c
}
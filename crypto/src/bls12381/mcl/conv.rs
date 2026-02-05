use miracl_core_bls12381::bls12381::{ecp::ECP, ecp2::ECP2};

// convert ECP to String representation of mcl_rust::G1
// can be converted to G1 by calling `let g1 = G1::from_str(&out, 16).unwrap();`
pub fn convert_ecp_to_mcl_g1_str(mut inp: ECP) -> String {
    inp.affine();
    let rx = inp.getpx().tostring().to_ascii_lowercase();
    let ry = inp.getpy().tostring().to_ascii_lowercase();

    format!("1 0x{} 0x{}", rx, ry)
}

// convert ECP2 to String representation of mcl_rust::G2
// can be converted to G2 by calling `let g2 = G2::from_str(&out, 16).unwrap();`
pub fn convert_ecp2_to_mcl_g2_str(mut inp: ECP2) -> String {
    inp.affine();
    let mut x = inp.getpx();
    let mut y = inp.getpy();

    let rxa = x.geta().tostring().to_ascii_lowercase();
    let rxb = x.getb().tostring().to_ascii_lowercase();
    let rya = y.geta().tostring().to_ascii_lowercase();
    let ryb = y.getb().tostring().to_ascii_lowercase();

    format!("1 0x{} 0x{} 0x{} 0x{}", rxa, rxb, rya, ryb)
}

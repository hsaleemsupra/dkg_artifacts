use miracl_core_bls12381::arch::Chunk;
use miracl_core_bls12381::bls12381::rom;
use miracl_core_bls12381::bls12381::{
    big::{BIG, NLEN},
    ecp::ECP,
    ecp2::ECP2,
    fp2::FP2,
};

pub const CURVE_PXA: [Chunk; NLEN] = [
    16824558786059980,
    181999107401930136,
    11283449788034611,
    247142785618212850,
    5115347856197160,
    146001675235273423,
    4090499503,
];
pub const CURVE_PXB: [Chunk; NLEN] = [
    98185304266089651,
    228006849425300456,
    129034268867688943,
    70995024897859755,
    191685991949177420,
    145210449928952163,
    6205438544,
];
pub const CURVE_PYA: [Chunk; NLEN] = [
    29369224775707601,
    137304348937173369,
    271677621103912788,
    262319085899146305,
    216226305296338627,
    119148497209621905,
    1938443697,
];
pub const CURVE_PYB: [Chunk; NLEN] = [
    40290804165772950,
    214253586234727122,
    256915076971183232,
    225277463365040504,
    96241129155525134,
    265460976847598722,
    6955614589,
];

pub const X: &str = "1490485673189267324327220854985940498515857427639219520252677586669310050426096250529683483057578053845695977302605";
pub const Y: &str = "1405772507307650904885814159424737301884803741041201599376687588686566229941847930862592328097124042659031385407926";

// curve order (same)
pub const CURVE_ORDER: [Chunk; NLEN] = rom::CURVE_ORDER;
// b = 4 from equation y^2 = x^3 + 4 (same)
pub const CURVE_B_I: isize = rom::CURVE_B_I;

pub const CURVE_BNX: [Chunk; NLEN] = rom::CURVE_BNX;
pub const FRB: [Chunk; NLEN] = rom::FRB;
pub const FRA: [Chunk; NLEN] = rom::FRA;
pub const CRU: [Chunk; NLEN] = rom::CRU;
pub const USE_GS_G2: bool = rom::USE_GS_G2;
pub const USE_GS_GT: bool = rom::USE_GS_GT;
pub const USE_GLV: bool = rom::USE_GLV;

pub fn g1_generator() -> ECP {
    ECP::generator()
}

pub fn g2_generator() -> ECP2 {
    ECP2::new_fp2s(
        &FP2::new_bigs(&BIG::new_ints(&CURVE_PXA), &BIG::new_ints(&CURVE_PXB)),
        &FP2::new_bigs(&BIG::new_ints(&CURVE_PYA), &BIG::new_ints(&CURVE_PYB)),
    )
}

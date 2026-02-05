use sha2::{ Sha512, Digest };
use miracl_core_bls12381::bls12381::{
    big::BIG,
    fp::FP,
    ecp::ECP,
    rom,
};

pub fn hash_to_fp(msg: &[u8]) -> FP {
    let dst = &mut Sha512::digest(msg)[..48];
    dst.reverse();
    let mut big = BIG::frombytes(dst);
    big.mod2m(381);
    let p = BIG { w: rom::MODULUS };
    if BIG::comp(&big, &p) >= 0 {
        big.mod2m(380);
    }
    FP::new_big(&big)
}

pub fn hash_to_ecp(msg: &[u8]) -> ECP {
    let fp = hash_to_fp(msg);

    let mut p= calc_bn(&fp);
    let cf = BIG::fromstring("396c8c005555e1568c00aaab0000aaab".to_string());

    p = p.mul(&cf);
    p
}

fn check_qr(x: &FP, jacobi: isize) -> Option<ECP> {
    let mut res = ECP::new_big(&x.redc());
    if res.is_infinity() {
        return None;
    }

    if res.getpy().jacobi() != jacobi {
        res.neg();
    }

    Some(res)
}

fn calc_bn(fp: &FP) -> ECP {
    let neg = FP::new_copy(fp).jacobi();
    assert!(!fp.iszilch());

    let mut w = FP::new_copy(fp);
    w.sqr();

    let c1 = FP::new_big(&BIG::fromstring("be32ce5fbeed9ca374d38c0ed41eefd5bb675277cdf12d11bc2fb026c41400045c03fffffffdfffd".to_string()));
    let c2 = FP::new_big(&BIG::fromstring("5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe".to_string()));

    w.add(&FP::new_int(4));
    w.add(&FP::new_int(1));
    assert!(!w.iszilch());
    w.inverse(None);
    w.mul(&c1);
    w.mul(fp);

    let mut x = FP::new_copy(&w);
    x.mul(fp);
    x.neg();
    x.add(&c2);
    if let Some(p) = check_qr(&x, neg) {
        return p;
    }

    x.neg();
    x.sub(&FP::new_int(1));
    if let Some(p) = check_qr(&x, neg) {
        return p;
    }

    x = FP::new_copy(&w);
    x.sqr();
    x.inverse(None);
    x.add(&FP::new_int(1));
    check_qr(&x, neg).unwrap()
}
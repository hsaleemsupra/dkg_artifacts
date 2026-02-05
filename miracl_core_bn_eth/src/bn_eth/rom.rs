/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use crate::arch::Chunk;
use crate::bn_eth::big::NLEN;

// BN254 Modulus
// Base Bits= 56
// David: fixed.
pub const MODULUS: [Chunk; NLEN] = [
    0x208c16d87cfd47,
    0x6a916871ca8d3c,
    0xb68181585d9781,
    0xe131a029b85045,
    0x30644e72];

// David: don't care -- this is never used.
pub const ROI: [Chunk; NLEN] = [0x12, 0x13A7, 0x80000000086121, 0x40000001BA344D, 0x25236482];

// David: fixed.
pub const R2MODP: [Chunk; NLEN] = [
    0xbb888f34693c46,
    0x1c4bb9be2ac0dd,
    0xc1a7aec3d9e1b9,
    0x3cb4fa22c83580,
    0x95e2ea9,
];

// David: fixed.
pub const MCONST: Chunk = 0xd20782e4866389;

//Hamza: fixed
// sqrt(-3) used in MCL
pub const Z0: [Chunk; NLEN] = [
    0xc68e62effffffd,
    0xc7e359b6b89eae,
    0x9d41a91759a9e4,
    0x00000000b3c4d7,
    0x0,
];

//Hamza: fixed
// (sqrt(-3) - 1)  / 2 used in MCL
pub const Z1: [Chunk; NLEN] = [
    0x63473177fffffe,
    0x63f1acdb5c4f57,
    0xcea0d48bacd4f2,
    0x0000000059e26b,
    0x0,
];

// David: fixed.
// pub const SQRTM3: [Chunk; NLEN] = [0xc68e62effffffd, 0xc7e359b6b89eae, 0x9d41a91759a9e4, 0x00000000b3c4d7, 0x0];
pub const SQRTM3: [Chunk; NLEN] = [
    0x59fdb3e87cfd4a,
    0xa2ae0ebb11ee8d,
    0x193fd84103ed9c,
    0xe131a029048b6e,
    0x30644e72,
    ];

// David: fixed.
pub const FRA: [Chunk; NLEN] = [
    0x0B35DADCC9E470,
    0x1E08292F2176D6,
    0xDD76E68B605C52,
    0x2865A7DFE8B99F,
    0x1284B71C,
];

// David: fixed.
pub const FRB: [Chunk; NLEN] = [
    0x5CF05F80F362AC,
    0x92778EEEC7E5CA,
    0xFE12150B8E7479,
    0xB4FAE7E6A6327C,
    0x246996F3,
];

pub const CURVE_COF_I: isize = 1;

// David: fixed.
pub const CURVE_B_I: isize = 3;

// David: fixed.
pub const CURVE_B: [Chunk; NLEN] = [0x3, 0x0, 0x0, 0x0, 0x0];

// David: fixed.
pub const CURVE_ORDER: [Chunk; NLEN] = [
    0xe1f593f0000001,
    0xe84879b9709143,
    0xb68181585d2833,
    0xe131a029b85045,
    0x30644e72,
];

// David: fixed.
pub const CURVE_GX: [Chunk; NLEN] = [0x1, 0x0, 0x0, 0x0, 0x0];

// David: fixed.
pub const CURVE_GY: [Chunk; NLEN] = [0x2, 0x0, 0x0, 0x0, 0x0];

pub const CURVE_HTPC: [Chunk; NLEN] = [0x1, 0x0, 0x0, 0x0, 0x0];

// David: fixed
pub const CURVE_BNX: [Chunk; NLEN] = [0xe992b44a6909f1, 0x44, 0x0, 0x0, 0x0];

pub const CURVE_COF: [Chunk; NLEN] = [0x1, 0x0, 0x0, 0x0, 0x0];

// David: fixed
pub const CRU: [Chunk; NLEN] = [
    0xBD44E5607CFD48,
    0x069FBB966E3DE4,
    0xE7E0ACCCB0C28F,
    0xE131A0295E6DD9,
    0x30644E72];

// David: fixed
pub const CURVE_PXA: [Chunk; NLEN] = [
    0xdebd5cd992f6ed,
    0x22d4f75edadd46,
    0x665e5c44796743,
    0x121f1e76426a00,
    0x1800deef,
];

// David: fixed
pub const CURVE_PXB: [Chunk; NLEN] = [
    0xe485b7aef312c2,
    0x493335a9e71297,
    0xb731fb5d25f1aa,
    0x920d483a7260bf,
    0x198e9393,
];

// David: fixed
pub const CURVE_PYA: [Chunk; NLEN] = [
    0xe6cc0166fa7daa,
    0xe7690c43d37b4c,
    0x808dcb408fe3d1,
    0xdb8c6deb4aab71,
    0x12c85ea5,
];

// David: fixed
pub const CURVE_PYB: [Chunk; NLEN] = [
    0xacdadcd122975b,
    0x313370b38ef355,
    0xad690c3395bc4b,
    0x585ff075ec9e99,
    0x90689d0,
];

// David: fixed.
pub const CURVE_W: [[Chunk; NLEN]; 2] = [
    [
        0xe4e1541221250b,
        0x8248eeb859fd0b,
        0x6f4d,
        0x0,
        0x0],
    [
        0x0ed02b5b2dec1e,
        0xe84879b97090ba,
        0xb68181585d2833,
        0xe131a029b85045,
        0x30644e72],
];

// David: fixed.
pub const CURVE_SB: [[[Chunk; NLEN]; 2]; 2] = [
    [
        [
            0x11bbeb7d4f1128,
            0x8248eeb859fc82,
            0x6f4d,
            0x0,
            0x0],
        [
            0x0ed02b5b2dec1e,
            0xe84879b97090ba,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72],
    ],
    [
        [
            0x0ed02b5b2dec1e,
            0xe84879b97090ba,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72],
        [
            0xfd143fdddedaf6,
            0x65ff8b01169437,
            0xb68181585cb8e6,
            0xe131a029b85045,
            0x30644e72],
    ],
];

// David: fixed.
pub const CURVE_WB: [[Chunk; NLEN]; 4] = [
    [
        0x7c3f9dd764c796,
        0xd6184f92c8aa21, 0x2519, 0x0, 0x0],
    [
        0xaeb2a50460853c,
        0xa72d504cc45b07,
        0xd76b9e5094e470,
        0xe131a0297c63fd,
        0x30644e72],
    [
        0x538ac254fbbda6,
        0x47bae5031a7603,
        0xc6f68fd4790652,
        0xe131a0299a5a21,
        0x30644e72,
    ],
    [
        0xa91a354292b3b3,
        0xd6184f92c8a997, 0x2519, 0x0, 0x0],
];

// David: fixed.
pub const CURVE_BB: [[[Chunk; NLEN]; 4]; 4] = [
    [
        [
            0xe992b44a6909f2,
            0x44,
            0x0,
            0x0,
            0x0,
        ],
        [
            0xe992b44a6909f1,
            0x44,
            0x0,
            0x0,
            0x0,
        ],
        [
            0xe992b44a6909f1,
            0x44,
            0x0,
            0x0,
            0x0,
        ],
        [
            0x0ed02b5b2dec1f,
            0xe84879b97090ba,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72,
        ],
    ],
    [
        [
            0x0ed02b5b2dec1e,
            0xe84879b97090ba,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72,
        ],
        [
            0xe992b44a6909f1,
            0x44,
            0x0,
            0x0,
            0x0,
        ],
        [
            0xe992b44a6909f2,
            0x44,
            0x0,
            0x0,
            0x0,
        ],
        [
            0xe992b44a6909f1,
            0x44,
            0x0,
            0x0,
            0x0,
        ],
    ],
    [
        [
            0x0ed02b5b2dec1f,
            0xe84879b97090ba,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72,
        ],
        [
            0x0ed02b5b2dec1e,
            0xe84879b97090ba,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72,
        ],
        [
            0x0ed02b5b2dec1e,
            0xe84879b97090ba,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72,
        ],
        [
            0x0ed02b5b2dec1e,
            0xe84879b97090ba,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72,
        ],
    ],
    [
        [
            0xf862dfa596f611,
            0xe84879b97090fe,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72],
        [
            0x3baac2c65bd83b,
            0xe84879b9709030,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72],
        [
            0xd3256894d213e1,
            0x89,
            0x0,
            0x0,
            0x0,
        ],
        [
            0xf862dfa596f611,
            0xe84879b97090fe,
            0xb68181585d2833,
            0xe131a029b85045,
            0x30644e72],
    ],
];

pub const USE_GLV: bool = true;
pub const USE_GS_G2: bool = true;
pub const USE_GS_GT: bool = true;
pub const GT_STRONG: bool = false;

/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/



use super::big::NLEN;
use super::hash_to_curve::HashAlgorithm;
use crate::arch::Chunk;
use crate::types::{CurvePairingType, CurveType, ModType, SexticTwist, SignOfX};

// Base Bits= 58
// bls381-sgx Modulus

pub const MODULUS: [Chunk; NLEN] = [
    0x1FEFFFFFFFFAAAB,
    0x2FFFFAC54FFFFEE,
    0x12A0F6B0F6241EA,
    0x213CE144AFD9CC3,
    0x2434BACD764774B,
    0x25FF9A692C6E9ED,
    0x1A0111EA3,
];
pub const R2MODP: [Chunk; NLEN] = [
    0x20639A1D5BEF7AE,
    0x1244C6462DD93E8,
    0x22D09B54E6E2CD2,
    0x111C4B63170E5DB,
    0x38A6DE8FB366399,
    0x4F16CFED1F9CBC,
    0x19EA66A2B,
];
pub const MCONST: Chunk = 0x1F3FFFCFFFCFFFD;
pub const FRA: [Chunk; NLEN] = [
    0x10775ED92235FB8,
    0x3A94F58F9E04F63,
    0x3D784BAB9C4F67,
    0x3F4F2F57D3DEC91,
    0x202C0D1F0FD603,
    0xAEC199F08C6FAD,
    0x1904D3BF0,
];
pub const FRB: [Chunk; NLEN] = [
    0xF78A126DDC4AF3,
    0x356B0535B1FB08B,
    0xEC971F63C5F282,
    0x21EDB1ECDBFB032,
    0x2231F9FB854A147,
    0x1B1380CA23A7A40,
    0xFC3E2B3,
];

pub const CURVE_COF_I: isize = 0;
pub const CURVE_A: isize = 0;
pub const CURVE_B_I: isize = 4;
pub const CURVE_B: [Chunk; NLEN] = [0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
pub const CURVE_ORDER: [Chunk; NLEN] = [
    0x3FFFFFF00000001,
    0x36900BFFF96FFBF,
    0x180809A1D80553B,
    0x14CA675F520CCE7,
    0x73EDA7,
    0x0,
    0x0,
];
pub const CURVE_GX: [Chunk; NLEN] = [
    0x33AF00ADB22C6BB,
    0x17A0FFE5E86BBFE,
    0x3A3F171BAC586C5,
    0x13E5DD2E4168538,
    0x4FA9AC0FC3688C,
    0x65F5E509A558E3,
    0x17F1D3A73,
];
pub const CURVE_GY: [Chunk; NLEN] = [
    0xAA232946C5E7E1,
    0x331D128A222B903,
    0x18CB2C04B3EDD03,
    0x25757402BD8036C,
    0x1741D8AE4FCF5E0,
    0xEAA83C68278C3B,
    0x8B3F481E,
];

pub const CURVE_BNX: [Chunk; NLEN] = [0x201000000010000, 0x34, 0x0, 0x0, 0x0, 0x0, 0x0];
pub const CURVE_COF: [Chunk; NLEN] = [0xAAAB0000AAAB, 0x3230015557855A3, 0x396, 0x0, 0x0, 0x0, 0x0];
pub const CURVE_CRU: [Chunk; NLEN] = [
    0x201FFFFFFFEFFFE,
    0x1F604D88280008B,
    0x293BE6F89688DE1,
    0x1DA83DDFAB76CE,
    0x3DF76CE51BA69C6,
    0x17C659CB,
    0x0,
];

pub const CURVE_PXA: [Chunk; NLEN] = [
    0x8056C8C121BDB8,
    0x300C9AA016EFBF5,
    0xB647AE3D1770BA,
    0x353E900EC0AD144,
    0x32DC51051C6E47A,
    0x23C2A449820149,
    0x24AA2B2F,
];
pub const CURVE_PXB: [Chunk; NLEN] = [
    0x1AC7D055D042B7E,
    0x33C4484E51755F9,
    0x21BBDC7F5049334,
    0x3426482D86AD769,
    0x88274F65596BD0,
    0x9C67D81F6B34E8,
    0x13E02B605,
];
pub const CURVE_PYA: [Chunk; NLEN] = [
    0x193548608B82801,
    0x2B2730EEB28A278,
    0x1A695160D12C923,
    0x2AA32F74E9DB50A,
    0x2DA2E351AADFD9B,
    0x9F5B8463327371,
    0xCE5D5277,
];
pub const CURVE_PYB: [Chunk; NLEN] = [
    0x2A9075FF05F79BE,
    0x1C349D73B07686A,
    0x12AB572E99AB3F3,
    0x1FA169D8EBC99D2,
    0x2BC28B99CB3E28,
    0x3A9CD330CAB34AC,
    0x606C4A02,
];
pub const CURVE_W: [[Chunk; NLEN]; 2] = [[0; NLEN]; 2];
pub const CURVE_SB: [[[Chunk; NLEN]; 2]; 2] = [[[0; NLEN]; 2]; 2];
pub const CURVE_WB: [[Chunk; NLEN]; 4] = [[0; NLEN]; 4];
pub const CURVE_BB: [[[Chunk; NLEN]; 4]; 4] = [[[0; NLEN]; 4]; 4];

pub const USE_GLV: bool = true;
pub const USE_GS_G2: bool = true;
pub const USE_GS_GT: bool = true;
pub const GT_STRONG: bool = false;

pub const MODBYTES: usize = 48;
pub const BASEBITS: usize = 58;

pub const MODBITS: usize = 381;
pub const MOD8: usize = 3;
pub const MODTYPE: ModType = ModType::NotSpecial;
pub const SH: usize = 25;

pub const CURVETYPE: CurveType = CurveType::Weierstrass;
pub const CURVE_PAIRING_TYPE: CurvePairingType = CurvePairingType::Bls;
pub const SEXTIC_TWIST: SexticTwist = SexticTwist::MType;
pub const ATE_BITS: usize = 65;
pub const SIGN_OF_X: SignOfX = SignOfX::NegativeX;
pub const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha256; // Hash algorithm for hash to curve
pub const HASH_TYPE: usize = 32; // Output size of hash algorithm
pub const AESKEY: usize = 16;

// BLS Standard Constants
/// L = ceil(ceil(log2(p) + 128) / 8)
pub const H2C_L: usize = 64;

// G1 h_eff
pub const H_EFF_G1: [Chunk; NLEN] = [0x201000000010001, 0x34, 0x0, 0x0, 0x0, 0x0, 0x0];

// Curve parameters of G2 ISO-3: y^2 = x^3 + ax + b
pub const SSWU_A1: [Chunk; NLEN] = [
    0xf428082d584c1d,
    0xdbe368383e5fd7,
    0x181aefd881ac989,
    0x14e0fb99aa363a2,
    0x2c96d4982b0ea98,
    0xee3a50cf5a4e80,
    0x144698a,
];
pub const SSWU_B1: [Chunk; NLEN] = [
    0x1cc48e98e172be0,
    0xc8568c5b3aa974,
    0x14fcef35ef55a2,
    0x3c3c93d01c282e7,
    0x753eee3b2016c1,
    0x5a200c0062c4ba,
    0x12e2908d1,
];
pub const SSWU_Z1: [Chunk; NLEN] = [0xb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];

// Curve parameters of G2 ISO-3: y^2 = x^3 + ax + b
pub const SSWU_A2_A: [Chunk; NLEN] = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
pub const SSWU_A2_B: [Chunk; NLEN] = [0xf0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
pub const SSWU_B2_A: [Chunk; NLEN] = [0x3f4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
pub const SSWU_B2_B: [Chunk; NLEN] = [0x3f4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
pub const SSWU_Z2_A: [Chunk; NLEN] = [
    0x1feffffffffaaa9,
    0x2ffffac54ffffee,
    0x12a0f6b0f6241ea,
    0x213ce144afd9cc3,
    0x2434bacd764774b,
    0x25ff9a692c6e9ed,
    0x1a0111ea3,
];
pub const SSWU_Z2_B: [Chunk; NLEN] = [
    0x1feffffffffaaaa,
    0x2ffffac54ffffee,
    0x12a0f6b0f6241ea,
    0x213ce144afd9cc3,
    0x2434bacd764774b,
    0x25ff9a692c6e9ed,
    0x1a0111ea3,
];

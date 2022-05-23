package owkeychain

import (
	"encoding/hex"
	"github.com/nbit99/go-owcrypt"
)

var (
	openwalletPrePath = "m/44'/88'"
)

type CoinType struct {
	hdIndex   uint32
	curveType uint32
}

//XXX[0]:hd扩展索引
//XXX[1]:曲线类型
var (
	Bitcoin  = CoinType{uint32(0), owcrypt.ECC_CURVE_SECP256K1}
	Ethereum = CoinType{uint32(1), owcrypt.ECC_CURVE_SECP256K1}
)

var (
	owprvPrefix = []byte{0x07, 0xa8, 0x10, 0x0c, 0x28}
	owpubPrefix = []byte{0x07, 0xa8, 0x10, 0x31, 0xa2}
	owpubPrefix_BLS = []byte{0x3e, 0x00, 0xfa, 0xea, 0x69}

	BitcoinPubkeyPrefix = []byte{0}
	BitcoinScriptPrefix = []byte{5}
)

var (
	curveorder_secp256k1 = []byte{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41}
	curveorder_secp256r1 = []byte{0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51}
	curveorder_sm2_std = []byte{0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x72,0x03,0xDF,0x6B,0x21,0xC6,0x05,0x2B,0x53,0xBB,0xF4,0x09,0x39,0xD5,0x41,0x23}
	curveorder_ed25519 = []byte{0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0xDE,0xF9,0xDE,0xA2,0xF7,0x9C,0xD6,0x58,0x12,0x63,0x1A,0x5C,0xF5,0xD3,0xED}
	curveoeder_bls12_381 = []byte{0x73,0xed,0xa7,0x53,0x29,0x9d,0x7d,0x48,0x33,0x39,0xd8,0x08,0x09,0xa1,0xd8,0x05,0x53,0xbd,0xa4,0x02,0xff,0xfe,0x5b,0xfe,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01}
)

func getCurveOrder(typeChoose uint32) []byte {
	ret := make([]byte, 32)
	switch typeChoose {
	case owcrypt.ECC_CURVE_SECP256K1, owcrypt.ECC_CURVE_ZIL_SECP256K1:
		copy(ret, curveorder_secp256k1)
		break
	case owcrypt.ECC_CURVE_SECP256R1:
		copy(ret, curveorder_secp256r1)
		break
	case owcrypt.ECC_CURVE_SM2_STANDARD:
		copy(ret, curveorder_sm2_std)
		break
	case owcrypt.ECC_CURVE_ED25519, owcrypt.ECC_CURVE_ED25519_NORMAL, owcrypt.ECC_CURVE_X25519, owcrypt.ECC_CURVE_CURVE25519_SHA256, owcrypt.ECC_CURVE_ED25519_NEM:
		copy(ret, curveorder_ed25519)
		break
	case owcrypt.ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL, owcrypt.ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG:
		copy(ret, curveoeder_bls12_381)
		break
	case owcrypt.ECC_CURVE_PASTA:
		//ret = owcrypt.GetCurveOrder(owcrypt.ECC_CURVE_PASTA)
		ret, _ = hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
		break
	default:
		return  nil
		break
	}
	return ret
}
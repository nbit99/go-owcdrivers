package rippleTransaction

import (
	"math/big"
)

//const (
//	minOffset        int64  = -96
//	maxOffset        int64  = 80
//	minValue         uint64 = 1000000000000000
//	maxValue         uint64 = 9999999999999999
//	maxNative        uint64 = 9000000000000000000
//	maxNativeNetwork uint64 = 100000000000000000
//	notNative        uint64 = 0x8000000000000000
//	positive         uint64 = 0x4000000000000000
//	maxNativeSqrt    uint64 = 3000000000
//	maxNativeDiv     uint64 = 2095475792 // MaxNative / 2^32
//	tenTo14          uint64 = 100000000000000
//	tenTo14m1        uint64 = tenTo14 - 1
//	tenTo17          uint64 = tenTo14 * 1000
//	tenTo17m1        uint64 = tenTo17 - 1
//	xrpPrecision     uint64 = 1000000
//)

//type Value struct {
//	native   bool
//	negative bool
//	num      uint64
//	offset   int64
//}

//func newValue(native, negative bool, num uint64, offset int64) *Value {
//	return &Value{
//		native:   native,
//		negative: negative,
//		num:      num,
//		offset:   offset,
//	}
//}

//func (v Value) IsNative() bool {
//	return v.native
//}
//
//func (v *Value) Bytes() []byte {
//	if v == nil {
//		return nil
//	}
//	var u uint64
//	if !v.negative && (v.num > 0 || v.IsNative()) {
//		u |= 1 << 62
//	}
//	if v.IsNative() {
//		u |= v.num & ((1 << 62) - 1)
//	} else {
//		u |= 1 << 63
//		u |= v.num & ((1 << 54) - 1)
//		if v.num > 0 {
//			u |= uint64(v.offset+97) << 54
//		}
//	}
//	var b [8]byte
//	binary.BigEndian.PutUint64(b[:], u)
//	return b[:]
//}

func getSignatureBytes(sp []byte) []byte {
	r := sp[:32]
	s := sp[32:]
	if r[0]&0x80 == 0x80 {
		r = append([]byte{0x00}, r...)
	} else {
		for i := 0; i < 32; i++ {
			if r[0] == 0 && r[1]&0x80 != 0x80 {
				r = r[1:]
			} else {
				break
			}
		}
	}
	if s[0]&0x80 == 0x80 {
		s = append([]byte{0}, s...)
	} else {
		for i := 0; i < 32; i++ {
			if s[0] == 0 && s[1]&0x80 != 0x80 {
				s = s[1:]
			} else {
				break
			}
		}
	}

	r = append([]byte{byte(len(r))}, r...)
	r = append([]byte{0x02}, r...)
	s = append([]byte{byte(len(s))}, s...)
	s = append([]byte{0x02}, s...)

	rs := append(r, s...)
	rs = append([]byte{byte(len(rs))}, rs...)
	rs = append([]byte{0x30}, rs...)
	rs = append([]byte{byte(len(rs))}, rs...)

	return rs
}

func getPublicKeyBytes(pubkey []byte) []byte {
	return append([]byte{byte(len(pubkey))}, pubkey...)
}

func getHashBytes(hash []byte) []byte {
	return append([]byte{byte(len(hash))}, hash...)
}

func serilizeS(sig []byte) []byte {
	s := sig[32:]
	numS := new(big.Int).SetBytes(s)
	numHalfOrder := new(big.Int).SetBytes(HalfCurveOrder)
	if numS.Cmp(numHalfOrder) > 0 {
		numOrder := new(big.Int).SetBytes(CurveOrder)
		numS.Sub(numOrder, numS)

		s = numS.Bytes()
		if len(s) < 32 {
			for i := 0; i < 32-len(s); i++ {
				s = append([]byte{0x00}, s...)
			}
		}
		return append(sig[:32], s...)
	}
	return sig
}

func memoToBytes(memo string) []byte {
	return append([]byte{byte(len(memo))}, []byte(memo)...)
}

const hextable = "0123456789ABCDEF"
//faster than fmt and need upper case!
func b2h(h []byte) []byte {
	b := make([]byte, len(h)*2)
	for i, v := range h {
		b[i*2] = hextable[v>>4]
		b[i*2+1] = hextable[v&0x0f]
	}
	return b
}


func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func max(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func abs(a int64) uint64 {
	if a < 0 {
		return uint64(-a)
	}
	return uint64(a)
}

//func hashValues(values []interface{}) (Hash256, error) {
//	var hash Hash256
//	hasher := sha512.New()
//	for _, v := range values {
//		if err := write(hasher, v); err != nil {
//			return hash, err
//		}
//	}
//	copy(hash[:], hasher.Sum(nil))
//	return hash, nil
//}
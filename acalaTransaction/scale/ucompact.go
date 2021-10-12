package scale

import "math/big"

type UCompact big.Int

func NewUCompact(value *big.Int) UCompact {
	return UCompact(*value)
}

func NewUCompactFromUInt(value uint64) UCompact {
	return NewUCompact(new(big.Int).SetUint64(value))
}

func (u *UCompact) Decode(decoder Decoder) error {
	ui, err := decoder.DecodeUintCompact()
	if err != nil {
		return err
	}

	*u = UCompact(*ui)
	return nil
}

func (u UCompact) Encode(encoder Encoder) error {
	err := encoder.EncodeUintCompact(big.Int(u))
	if err != nil {
		return err
	}
	return nil
}


package btcLikeTxDriver

const (
	P2PKHPrefix  = byte(0x6F)
	P2SHPrefix   = byte(0xC4)
	Bech32Prefix = "tb1"
)

const (
	SequenceFinal        = uint32(0xFFFFFFFF)
	SequenceMaxBip125RBF = uint32(0xFFFFFFFD)
)

var (
	SegWitSymbol  = byte(0)
	SegWitVersion = byte(1)
	SigHashAll    = byte(1)
)

var (
	OpCodeHash160     = byte(0xA9)
	OpCodeEqual       = byte(0x87)
	OpCodeEqualVerify = byte(0x88)
	OpCodeCheckSig    = byte(0xAC)
	OpCodeDup         = byte(0x76)
	OpCode_1          = byte(0x51)
	OpCheckMultiSig   = byte(0xAE)
)

var (
	MaxScriptElementSize = 520
	CurveOrder           = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}
	HalfCurveOrder       = []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0}
)

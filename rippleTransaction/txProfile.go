package rippleTransaction

const (
	AddressPrefix        byte   = 0x00
	PAYMENT              uint16 = 0x00
	HP_TRANSACTION_SIGN  uint32 = 0x53545800
	TxCanonicalSignature uint32 = 0x80000000
	// Payment flags
	TxNoDirectRipple uint32 = 0x00010000
	TxPartialPayment uint32 = 0x00020000
	TxLimitQuality   uint32 = 0x00040000
	TxCircle         uint32 = 0x00080000 // Not implemented
)

const (
	ST_UINT16  uint8 = 1
	ST_UINT32  uint8 = 2
	ST_AMOUNT  uint8 = 6
	ST_VL      uint8 = 7
	ST_ACCOUNT uint8 = 8
	ST_OBJECT  uint8 = 14
	ST_ARRAY   uint8 = 15
	ST_PATHSET   uint8 = 18
)

var (
	CurveOrder     = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}
	HalfCurveOrder = []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0}
)

var encodings = map[string]enc{
	"TransactionType":    enc{ST_UINT16, 2},
	"Flags":              enc{ST_UINT32, 2},
	"Sequence":           enc{ST_UINT32, 4},
	"DestinationTag":     enc{ST_UINT32, 14},
	"LastLedgerSequence": enc{ST_UINT32, 27},
	"Amount":             enc{ST_AMOUNT, 1},
	"Fee":                enc{ST_AMOUNT, 8},
	"SigningPubKey":      enc{ST_VL, 3},
	"TxnSignature":       enc{ST_VL, 4},
	"Account":            enc{ST_ACCOUNT, 1},
	"Owner":              enc{ST_ACCOUNT, 2},
	"Destination":        enc{ST_ACCOUNT, 3},
	"Memos":              enc{ST_ARRAY, 9},
	"Memo":               enc{ST_OBJECT, 10},
	"MemoType":           enc{ST_VL, 12},
	"MemoData":           enc{ST_VL, 13},
	"MemoFormat":         enc{ST_VL, 14},
	"EndOfObject":        enc{ST_OBJECT, 1},
	"EndOfArray":         enc{ST_ARRAY, 1},
	"Paths":              enc{ST_PATHSET, 1},
	"SendMax":            enc{ST_AMOUNT, 9},
	//"TokenAmount":        enc{ST_OBJECT, 3},
	//"currency":           enc{ST_VL, 1},
	//"value":              enc{ST_VL, 1},
	//"issuer":             enc{ST_VL, 1},
}

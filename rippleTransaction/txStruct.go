package rippleTransaction

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	owcrypt "github.com/nbit99/go-owcrypt"
)

/**
{
  "TransactionType" : "Payment",
  "Account" : "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn",
  "Destination" : "ra5nK24KXen9AHvsdFTKHSANinZseWnPcX",
  "Amount" : {
     "currency" : "USD",
     "value" : "1",
     "issuer" : "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn"
  },
  "Fee": "12",
  "Flags": 2147483648,
  "Sequence": 2,
}

 */

type CurrencyAmount struct {
	Currency     string
	Value        string
	Issuer       string
}

type TxStruct struct {
	TransactionType    []byte
	Flags              []byte
	Sequence           []byte
	LastLedgerSequence []byte
	Amount             []byte
	Fee                []byte
	SigningPubKey      []byte
	TxnSignature       []byte
	Account            []byte
	Destination        []byte
	DestinationTag     []byte
	Memos              []byte
	Paths              []byte
	SendMax        	   []byte //如果SendMax交易指令中省略了该字段，则认为它等于Amount
	//DeliverMin         []byte
}

func getTransactionTypeBytes(txType uint16) []byte {
	enc := getEncBytes(encodings["TransactionType"])
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, txType)
	return append(enc, typeBytes...)
}
func getFlagsBytes(flags uint32) []byte {
	enc := getEncBytes(encodings["Flags"])
	flagsBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(flagsBytes, flags)
	return append(enc, flagsBytes...)
}

func getSequenceBytes(sequence uint32) []byte {
	enc := getEncBytes(encodings["Sequence"])
	sequenceBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sequenceBytes, sequence)
	return append(enc, sequenceBytes...)
}

func getDestinationTagBytes(tag int64) []byte {
	if tag < 0 {
		return nil
	}
	enc := getEncBytes(encodings["DestinationTag"])
	tagBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tagBytes, uint32(tag))
	return append(enc, tagBytes...)
}

func getLastLedgerSequenceBytes(ledgerSequence uint32) []byte {
	enc := getEncBytes(encodings["LastLedgerSequence"])
	sequenceBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sequenceBytes, ledgerSequence)
	return append(enc, sequenceBytes...)
}

func getAmountBytes(amount uint64) ([]byte, error) {
	if amount == 0 {
		return nil, errors.New("Amount cannot be zero!")
	}
	enc := getEncBytes(encodings["Amount"])
	amountValue := newValue(true, false, amount, 0)
	return append(enc, amountValue.Bytes()...), nil
}

func getCurrencyAmountBytes(amount *Amount) []byte {

	bytes := getEncBytes(encodings["Amount"])

	amountBytes := amount.Bytes()//json.Marshal(amount)

	bytes = append(bytes, amountBytes...)

	return bytes
}

func getSendMaxBytes(sendMax *Amount) []byte {

	bytes := getEncBytes(encodings["SendMax"])

	amountBytes := sendMax.Bytes()

	bytes = append(bytes, amountBytes...)

	return bytes
}

func getFeeBytes(fee uint64) ([]byte, error) {
	if fee == 0 {
		return nil, errors.New("Fee cannot be zero!")
	}
	enc := getEncBytes(encodings["Fee"])
	feeValue := newValue(true, false, fee, 0)
	return append(enc, feeValue.Bytes()...), nil
}

func getSigningPubKeyBytes(pubkey string) ([]byte, error) {
	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil || pubkeyBytes == nil || len(pubkeyBytes) != 33 || (pubkeyBytes[0] != 0x02 && pubkeyBytes[0] != 0x03) {
		return nil, errors.New("Invalid public key data!")
	}
	enc := getEncBytes(encodings["SigningPubKey"])
	return append(enc, getPublicKeyBytes(pubkeyBytes)...), nil
}

func getTxnSignatureBytes(signature string) ([]byte, error) {
	sigBytes, err := hex.DecodeString(signature)
	if err != nil || sigBytes == nil || len(sigBytes) != 64 {
		return nil, errors.New("Invalid signature data!")
	}
	enc := getEncBytes(encodings["TxnSignature"])
	return append(enc, getSignatureBytes(sigBytes)...), nil
}

func getAccountBytes(address, typo string) ([]byte, error) {
	hashBytes, err := GetProgramHashFromAddress(address)
	if err != nil {
		if typo == "Account" {
			return nil, errors.New("Invalid from address!")
		}
		return nil, errors.New("Invalid to address!")
	}
	hashBytes = getHashBytes(hashBytes)
	enc := getEncBytes(encodings[typo])
	return append(enc, hashBytes...), nil
}

func getMemosBytes(memoType, memoData, memoFormat string) []byte {
	if memoData != "" {
		memoBytes := getEncBytes(encodings["Memos"])
		memoBytes = append(memoBytes, getEncBytes(encodings["Memo"])...)

		if memoType != "" {
			memoBytes = append(memoBytes, getEncBytes(encodings["MemoType"])...)
			memoBytes = append(memoBytes, memoToBytes(memoType)...)
		}

		memoBytes = append(memoBytes, getEncBytes(encodings["MemoData"])...)
		memoBytes = append(memoBytes, memoToBytes(memoData)...)

		if memoFormat != "" {
			memoBytes = append(memoBytes, getEncBytes(encodings["MemoFormat"])...)
			memoBytes = append(memoBytes, memoToBytes(memoFormat)...)
		}
		memoBytes = append(memoBytes, getEncBytes(encodings["EndOfObject"])...)
		memoBytes = append(memoBytes, getEncBytes(encodings["EndOfArray"])...)
		return memoBytes
	}
	return nil
}

func NewTxStruct(from, pubkey string, sequence uint32, to string, amount []byte, fee uint64, signature string, destinationTag int64, lastLedgerSequence uint32, memoType, memoData, memoFormat string, flags uint32) (*TxStruct, error) {
	var (
		txStruct TxStruct
		err      error
	)

	txStruct.TransactionType = getTransactionTypeBytes(PAYMENT)
	txStruct.Flags = getFlagsBytes(flags)
	txStruct.Sequence = getSequenceBytes(sequence)
	txStruct.DestinationTag = getDestinationTagBytes(destinationTag)
	txStruct.LastLedgerSequence = getLastLedgerSequenceBytes(lastLedgerSequence)
	txStruct.Amount = amount//getAmountBytes(amount)
	//if err != nil {
	//	return nil, err
	//}
	txStruct.Fee, err = getFeeBytes(fee)
	if err != nil {
		return nil, err
	}
	txStruct.SigningPubKey, err = getSigningPubKeyBytes(pubkey)
	if err != nil {
		return nil, err
	}
	if signature != "" {
		txStruct.TxnSignature, err = getTxnSignatureBytes(signature)
		if err != nil {
			return nil, err
		}
	}
	txStruct.Account, err = getAccountBytes(from, "Account")
	if err != nil {
		return nil, err
	}
	txStruct.Destination, err = getAccountBytes(to, "Destination")
	if err != nil {
		return nil, err
	}

	txStruct.Memos = getMemosBytes(memoType, memoData, memoFormat)

	//txStruct.Paths = getPathsBytes(pathSet)

	//if sendMax != nil {
	//	txStruct.SendMax = getSendMaxBytes(sendMax)
	//}

	return &txStruct, nil
}

func getPathsBytes(pathSet PathSet) []byte {
	if len(pathSet) > 0 {
		pathBytes := getEncBytes(encodings["Paths"])

		pathSetBytes, err := pathSet.Marshal()

		if err != nil {
			return nil
		}
		pathBytes = append(pathBytes, pathSetBytes...)
		return pathBytes
	}
	return nil
}

func (tx TxStruct) ToEmptyRawWiths() string {
	ret := []byte{}
	ret = append(ret, tx.TransactionType...)
	ret = append(ret, tx.Flags...)
	ret = append(ret, tx.Sequence...)
	ret = append(ret, tx.DestinationTag...)
	ret = append(ret, tx.LastLedgerSequence...)
	ret = append(ret, tx.Amount...)
	ret = append(ret, tx.Fee...)
	//ret = append(ret, tx.SendMax...)
	ret = append(ret, tx.SigningPubKey...)
	pre := hex.EncodeToString(ret)
	ret = []byte{}
	ret = append(ret, tx.Account...)
	ret = append(ret, tx.Destination...)
	ret = append(ret, tx.Memos...)
	//ret = append(ret, tx.Paths...)
	last := hex.EncodeToString(ret)
	return pre + "s" + last
}

func (tx TxStruct) ToBytes() []byte {
	ret := []byte{}
	ret = append(ret, tx.TransactionType...)
	ret = append(ret, tx.Flags...)
	ret = append(ret, tx.Sequence...)
	ret = append(ret, tx.DestinationTag...)
	ret = append(ret, tx.LastLedgerSequence...)
	ret = append(ret, tx.Amount...)
	ret = append(ret, tx.Fee...)
	//ret = append(ret, tx.SendMax...)
	ret = append(ret, tx.SigningPubKey...)
	ret = append(ret, tx.TxnSignature...)
	ret = append(ret, tx.Account...)
	ret = append(ret, tx.Destination...)
	ret = append(ret, tx.Memos...)
	//ret = append(ret, tx.Paths...)

	return ret
}

func (tx TxStruct) GetHash() []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, HP_TRANSACTION_SIGN)
	tx.TxnSignature = nil
	return owcrypt.Hash(append(data, tx.ToBytes()...), 0, owcrypt.HASH_ALG_SHA512)[:32]
}

func getHashFromEmptyRawHex(emptyTrans string) ([]byte, error) {
	emptyTrans = strings.Replace(emptyTrans, "s", "", -1)
	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return nil, errors.New("Invalid empty raw transaction data!")
	}
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, HP_TRANSACTION_SIGN)

	return owcrypt.Hash(append(data, txBytes...), 0, owcrypt.HASH_ALG_SHA512)[:32], nil
}

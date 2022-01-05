package rippleTransaction

import (
	"encoding/hex"
	"errors"
	"strings"

	owcrypt "github.com/nbit99/go-owcrypt"
)

func CreateEmptyRawTransactionAndHash(from, pubkey string, destinationTag int64, sequence uint32, to string, amount, fee uint64, lastLedgerSequence uint32, memoType, memoData, memoFormat string) (string, string, error) {
	amountBytes, err := getAmountBytes(amount)
	if err != nil {
		return "", "", err
	}
	tx, err := NewTxStruct(from, pubkey, sequence, to, amountBytes, fee, "", destinationTag, lastLedgerSequence, memoType, memoData, memoFormat,TxCanonicalSignature)
	if err != nil {
		return "", "", err
	}
	return tx.ToEmptyRawWiths(), hex.EncodeToString(tx.GetHash()), nil
}

func CreateTokenEmptyRawTransactionAndHash(from, pubkey string, destinationTag int64, sequence uint32, to string, amount *Amount, fee uint64, lastLedgerSequence uint32, memoType, memoData, memoFormat string) (string, string, error) {
	amountBytes := getCurrencyAmountBytes(amount)
	tx, err := NewTxStruct(from, pubkey, sequence, to, amountBytes, fee, "", destinationTag, lastLedgerSequence, memoType, memoData, memoFormat, TxPartialPayment)
	if err != nil {
		return "", "", err
	}
	return tx.ToEmptyRawWiths(), hex.EncodeToString(tx.GetHash()), nil
}

func SignRawTransaction(hash string, prikey []byte) (string, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return "", errors.New("Invalid transaction hash string!")
	}
	signature, _, reCode := owcrypt.Signature(prikey, nil, hashBytes, owcrypt.ECC_CURVE_SECP256K1)
	if reCode != owcrypt.SUCCESS {
		return "", errors.New("failed to sign transaction hash!")
	}
	return hex.EncodeToString(serilizeS(signature)), nil
}

func VerifyAndCombinRawTransaction(emptyTrans string, signature, publicKey string) (bool, string) {
	hash, err := getHashFromEmptyRawHex(emptyTrans)
	if err != nil {
		return false, ""
	}
	pubkeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, ""
	}
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, ""
	}
	pubkeyBytes = owcrypt.PointDecompress(pubkeyBytes, owcrypt.ECC_CURVE_SECP256K1)[1:]
	if owcrypt.SUCCESS != owcrypt.Verify(pubkeyBytes, nil, hash, sigBytes, owcrypt.ECC_CURVE_SECP256K1) {
		return false, ""
	}
	txnSignature, _ := getTxnSignatureBytes(signature)
	return true, strings.Replace(emptyTrans, "s", hex.EncodeToString(txnSignature), -1)
}

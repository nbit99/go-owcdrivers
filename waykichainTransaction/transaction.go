package waykichainTransaction

import (
	"encoding/hex"
	"errors"

	owcrypt "github.com/nbit99/go-owcrypt"
)

// fromUserID - user id when txType is TxType_COMMON
// fromUserID - publick key hex when txType is TxType_REGACCT
// to - contract Hex when txType is TxType_CONTRACT
// appID - contract regID when txType is TxType_CONTRACT
// appID - coin name when txType is TxType_UcoinTransfer
func CreateEmptyRawTransactionAndHash(fromUserID, to, appID string, amount, fee, validHeight int64, txType byte) (string, string, error) {
	if txType == TxType_COMMON {
		txCommon, err := NewCommonTx(fromUserID, to, amount, fee, validHeight)
		if err != nil {
			return "", "", err
		}
		return hex.EncodeToString(txCommon.ToBytes()), hex.EncodeToString(txCommon.GetHash()), nil
	} else if txType == TxType_REGACCT {
		txRegisterAccount, err := NewRegisterAccountTx(fromUserID, fee, validHeight)
		if err != nil {
			return "", "", err
		}

		return hex.EncodeToString(txRegisterAccount.ToBytes()), hex.EncodeToString(txRegisterAccount.GetHash()), nil
	} else if txType == TxType_CONTRACT {
		txContract, err := NewCallContractTx(fromUserID, appID, to, validHeight, fee, amount)
		if err != nil {
			return "", "", err
		}

		return hex.EncodeToString(txContract.ToBytes()), hex.EncodeToString(txContract.GetHash()), nil
	} else if txType == TxType_UcoinTransfer {
		txUcoinTransfer, err := NewUcoinTransferTx(fromUserID, to, appID, validHeight, fee, amount)
		if err != nil {
			return "", "", err
		}

		return hex.EncodeToString(txUcoinTransfer.ToBytes()), hex.EncodeToString(txUcoinTransfer.GetHash()), nil
	}
	return "", "", errors.New("Unknown transaction type")
}

func SignRawTransaction(hash string, prikey []byte) ([]byte, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, errors.New("Invalid transaction hash string!")
	}

	signature, _, retCode := owcrypt.Signature(prikey, nil, hashBytes, owcrypt.ECC_CURVE_SECP256K1)
	if retCode != owcrypt.SUCCESS {
		return nil, errors.New("Failed to sign transaction hash!")
	}

	return signature, nil
}

func VerifyAndCombineRawTransaction(emptyTrans string, sigPub SigPub) (bool, string) {
	hash, err := getHashFromEmptyRawTrans(emptyTrans)
	if err != nil {
		return false, ""
	}
	pubkey := owcrypt.PointDecompress(sigPub.PublicKey, owcrypt.ECC_CURVE_SECP256K1)[1:]

	if owcrypt.SUCCESS != owcrypt.Verify(pubkey, nil, hash, sigPub.Signature, owcrypt.ECC_CURVE_SECP256K1) {
		return false, ""
	}

	return true, emptyTrans + hex.EncodeToString(sigPub.ToBytes())
}

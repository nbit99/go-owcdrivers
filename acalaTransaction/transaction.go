package acalaTransaction

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/nbit99/go-owcdrivers/acalaTransaction/scale"
	"github.com/nbit99/go-owcdrivers/polkadotTransaction"
	"github.com/nbit99/go-owcrypt"
	"math/big"
)

func (ts TxStruct) CreateEmptyTransactionAndMessage(transferCode string) (string, string, error) {

	tp, err := ts.NewTxPayLoad(transferCode)
	if err != nil {
		return "", "", err
	}

	return ts.ToJSONString(), tp.ToBytesString(), nil
}

func (tx TxStruct) NewTxPayLoad(transfer_code string) (*polkadotTransaction.TxPayLoad, error) {
	var tp polkadotTransaction.TxPayLoad
	method, err := NewMethodTransfer(tx.RecipientPubkey, tx.Amount)
	if err != nil {
		return nil, err
	}

	tp.Method, err = method.ToBytes(transfer_code)
	if err != nil {
		return nil, err
	}

	if tx.BlockHeight == 0 {
		return nil, errors.New("invalid block height")
	}

	tp.Era = polkadotTransaction.GetEra(tx.BlockHeight)

	if tx.Nonce == 0 {
		tp.Nonce = []byte{0}
	} else {
		nonce := polkadotTransaction.Encode(uint64(tx.Nonce))
		tp.Nonce, _ = hex.DecodeString(nonce)
	}

	if tx.Fee.Cmp(big.NewInt(0)) < 0 {
		//return nil, errors.New("a none zero fee must be payed")
		tp.Fee = []byte{0}
	} else {
		tp.Fee, err = EncodeToBytes(scale.NewUCompact(tx.Fee))
		if err != nil {
			return nil, err
		}
	}

	specv := make([]byte, 4)
	binary.LittleEndian.PutUint32(specv, tx.SpecVersion)
	tp.SpecVersion = specv

	txv := make([]byte, 4)
	binary.LittleEndian.PutUint32(txv, tx.TxVersion)
	tp.TxVersion = txv

	genesis, err := hex.DecodeString(tx.GenesisHash)
	if err != nil || len(genesis) != 32 {
		return nil, errors.New("invalid genesis hash")
	}

	tp.GenesisHash = genesis

	block, err := hex.DecodeString(tx.BlockHash)
	if err != nil || len(block) != 32 {
		return nil, errors.New("invalid block hash")
	}

	tp.BlockHash = block

	return &tp, nil
}

func (tx TxStruct) ToJSONString() string {
	j, _ := json.Marshal(tx)

	return string(j)
}

func NewTxStructFromJSON(j string) (*TxStruct, error) {

	ts := TxStruct{}

	err := json.Unmarshal([]byte(j), &ts)

	if err != nil {
		return nil, err
	}

	return &ts, nil
}

func (ts TxStruct) GetSignedTransaction(transfer_code, signature string) (string, error) {

	signed := make([]byte, 0)

	signed = append(signed, polkadotTransaction.SigningBitV4)

	if transfer_code != "0600" {//kilt 不能加0
		signed = append(signed, 0x00)
	}

	//fmt.Printf("version:%x\n", signed)

	if polkadotTransaction.AccounntIDFollow {
		signed = append(signed, 0xff)
	}

	from, err := hex.DecodeString(ts.SenderPubkey)
	if err != nil || len(from) != 32 {
		return "", nil
	}

	signed = append(signed, from...)

	signed = append(signed, 0x00) // ed25519

	//fmt.Printf("from:%x \n", signed)

	sig, err := hex.DecodeString(signature)
	if err != nil || len(sig) != 64 {
		return "", nil
	}
	signed = append(signed, sig...)

	//fmt.Printf("sign:%x \n", signed)

	if ts.BlockHeight == 0 {
		return "", errors.New("invalid block height")
	}

	signed = append(signed, polkadotTransaction.GetEra(ts.BlockHeight)...)

	//fmt.Printf("height:%x\n", signed)

	if ts.Nonce == 0 {
		signed = append(signed, 0)
	} else {
		nonce := polkadotTransaction.Encode(uint64(ts.Nonce))

		nonceBytes, _ := hex.DecodeString(nonce)
		signed = append(signed, nonceBytes...)
	}

	feeBytes := make([]byte, 0)
	if ts.Fee.Cmp(big.NewInt(0)) <= 0 {
		//return "", errors.New("a none zero fee must be payed")
		feeBytes = []byte{0}
	} else {
		feeBytes, _ = EncodeToBytes(scale.NewUCompact(ts.Fee))
	}

	signed = append(signed, feeBytes...)

	method, err := NewMethodTransfer(ts.RecipientPubkey, ts.Amount)
	if err != nil {
		return "", err
	}

	methodBytes, err := method.ToBytes(transfer_code)
	if err != nil {
		return "", err
	}

	signed = append(signed, methodBytes...)

	length := polkadotTransaction.Encode(uint64(len(signed)))
	lengthBytes, _ := hex.DecodeString(length)
	return "0x" + hex.EncodeToString(lengthBytes) + hex.EncodeToString(signed), nil
}

func NewMethodTransfer(pubkey string, amount *big.Int) (*polkadotTransaction.MethodTransfer, error) {
	pubBytes, err := hex.DecodeString(pubkey)
	if err != nil || len(pubBytes) != 32 {
		return nil, errors.New("invalid dest public key")
	}

	if amount.Cmp(big.NewInt(0)) <= 0 {
		return nil, errors.New("zero amount")
	}

	amountBytes, err := EncodeToBytes(scale.NewUCompact(amount))
	if err != nil {
		return nil, err
	}
	return &polkadotTransaction.MethodTransfer{
		DestPubkey: pubBytes,
		Amount:     amountBytes,
	}, nil
}

func EncodeToBytes(value interface{}) ([]byte, error) {
	var buffer = bytes.Buffer{}
	err := scale.NewEncoder(&buffer).Encode(value)
	if err != nil {
		return buffer.Bytes(), err
	}
	return buffer.Bytes(), nil
}

func VerifyAndCombineTransaction(transferCode, emptyTrans, signature string) (string, bool) {
	ts, err := NewTxStructFromJSON(emptyTrans)
	if err != nil {
		return "", false
	}

	tp, err := ts.NewTxPayLoad(transferCode)
	if err != nil {
		return "", false
	}

	msg, _ := hex.DecodeString(tp.ToBytesString())

	pubkey, _ := hex.DecodeString(ts.SenderPubkey)

	sig, err := hex.DecodeString(signature)
	if err != nil || len(sig) != 64 {
		return "", false
	}

	if owcrypt.SUCCESS != owcrypt.Verify(pubkey, nil, msg, sig, owcrypt.ECC_CURVE_ED25519) {
		return "", false
	}

	signned, err := ts.GetSignedTransaction(transferCode, signature)
	if err != nil {
		return "", false
	}

	return signned, true
}

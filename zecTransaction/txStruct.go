package zecTransaction

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/codahale/blake2"
	"github.com/golang/protobuf/proto"
)

const (
	SAPLING_VERSION_GROUP_ID = 0x892f2085
	SAPLING_TX_VERSION       = 4

	fOverwintered     = true
	nVersionGroupId   = SAPLING_VERSION_GROUP_ID
	nVersion          = SAPLING_TX_VERSION
	consensusBranchId = 0xe9ff75a6
)

// Hash type bits from the end of a signature.
const (
	ZEC_SigHashOld          uint32 = 0x0
	ZEC_SigHashAll          uint32 = 0x1
	ZEC_SigHashNone         uint32 = 0x2
	ZEC_SigHashSingle       uint32 = 0x3
	ZEC_SigHashAnyOneCanPay uint32 = 0x80

	// sigHashMask defines the number of bits of the hash type which is used
	// to identify which outputs are signed.
	ZEC_sigHashMask = 0x1f
)

const (
	sighashMask                 = 0x1f
	blake2BSighash              = "ZcashSigHash"
	prevoutsHashPersonalization = "ZcashPrevoutHash"
	sequenceHashPersonalization = "ZcashSequencHash"
	outputsHashPersonalization  = "ZcashOutputsHash"

	versionOverwinter        int32  = 3
	versionOverwinterGroupID uint32 = 0x3C48270
	versionSapling                  = 4
	versionSaplingGroupID           = 0x892f2085
)

/**
this.joinsplits = []
    this.joinsplitPubkey = []
    this.joinsplitSig = []
    // ZCash version >= 3
    this.overwintered = 0  // 1 if the transaction is post overwinter upgrade, 0 otherwise
    this.versionGroupId = 0  // 0x03C48270 (63210096) for overwinter and 0x892F2085 (2301567109) for sapling
    this.expiryHeight = 0  // Block height after which this transactions will expire, or 0 to disable expiry
    // ZCash version >= 4
    this.valueBalance = 0
    this.vShieldedSpend = []
    this.vShieldedOutput = []
    this.bindingSig = 0
    // Must be updated along with version
    this.consensusBranchId = network.consensusBranchId[this.version]
*/

type Transaction struct {
	Version []byte
	//VersionGroupID     []byte
	Vins     []TxIn
	Vouts    []TxOut
	LockTime []byte
	Witness  bool
	//IsOverwinter       bool
	//ExpiryHeight       []byte

	//JoinsplitPubkey  []byte
	//JoinsplitSig     []byte
	// ZCash version >= 3
	Overwintered   bool   // 1 if the transaction is post overwinter upgrade, 0 otherwise
	VersionGroupId []byte // 0x03C48270 (63210096) for overwinter and 0x892F2085 (2301567109) for sapling
	ExpiryHeight   []byte // Block height after which this transactions will expire, or 0 to disable expiry
	// ZCash version >= 4
	//ValueBalance []byte
	//VShieldedSpend []byte
	//VShieldedOutput []byte
	//bindingSig []byte
	// Must be updated along with version
	ConsensusBranchId []byte //network.consensusBranchId[this.version]
}

func newEmptyTransaction(vins []Vin, vouts []Vout, lockTime uint32, replaceable bool, addressPrefix AddressPrefix) (*Transaction, error) {
	txIn, err := newTxInForEmptyTrans(vins)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(txIn); i++ {
		txIn[i].setSequence(lockTime, replaceable)
	}

	txOut, err := newTxOutForEmptyTrans(vouts, addressPrefix)
	if err != nil {
		return nil, err
	}

	version := uint32ToLittleEndianBytes(DefaultTxVersion | (1 << 31))
	locktime := uint32ToLittleEndianBytes(lockTime)

	//zeroBytes := uint32ToLittleEndianBytes(0)

	versionGroupId := uint32ToLittleEndianBytes(nVersionGroupId)

	branchId := uint32ToLittleEndianBytes(consensusBranchId)

	expiryHeight := uint32ToLittleEndianBytes(0)

	return &Transaction{version, txIn, txOut, locktime, false,
		fOverwintered, versionGroupId, expiryHeight, branchId}, nil
}

/**
 * Build a hash for all or none of the transaction inputs depending on the hashtype
 * @param hashType
 * @returns double SHA-256, 256-bit BLAKE2b hash or 256-bit zero if doesn't apply
 */
func (t Transaction) getPrevoutHash() {

	ret := []byte{}

	for _, in := range t.Vins {
		ret = append(ret, in.TxID...) //4
		ret = append(ret, in.Vout...)
	}

	//var bufferWriter = new BufferWriter(Buffer.allocUnsafe(36 * this.ins.length))
	//this.ins.forEach(function (txIn) {
	//	bufferWriter.writeSlice(txIn.hash)
	//	bufferWriter.writeUInt32(txIn.index)
	//})
	//return this.getBlake2bHash(bufferWriter.buffer, 'ZcashPrevoutHash')

}

//Transaction.prototype.getBlake2bHash = function (bufferToHash, personalization) {
//var out = Buffer.allocUnsafe(32)
//return blake2b(out.length, null, null, Buffer.from(personalization)).update(bufferToHash).digest(out)
//}

//func (t Transaction) encodeToBytes2(SegwitON bool) ([]byte, error) {
//
//}

// calculateHashPrevOuts calculates a single hash of all the previous
// outputs (txid:index) referenced within the passed transaction. This
// calculated hash can be re-used when validating all inputs spending segwit
// outputs, with a signature hash type of SigHashAll. This allows validation to
// re-use previous hashing computation, reducing the complexity of validating
// SigHashAll inputs from  O(N^2) to O(N).
func (t Transaction) calculateHashPrevOuts(hashType uint32) ([]byte, error) {
	if !(hashType&ZEC_SigHashAnyOneCanPay == 0) {
		return get32ZeroHash(), nil
	}

	var b bytes.Buffer
	for _, in := range t.Vins {
		// First write out the 32-byte transaction ID one of whose outputs are
		// being referenced by this input.
		b.Write(in.TxID)
		// Next, we'll encode the index of the referenced output as a little
		// endian integer.
		//var buf [4]byte
		//binary.LittleEndian.PutUint32(buf[:], in.Vout)
		b.Write(in.Vout)
	}

	return blake2b(b.Bytes(), []byte(prevoutsHashPersonalization))
}

func get32ZeroHash() []byte {
	zeroBytes := [32]byte{}

	return zeroBytes[:]
}

// calculateHashSequence computes an aggregated hash of each of the
// sequence numbers within the inputs of the passed transaction. This single
// hash can be re-used when validating all inputs spending segwit outputs, which
// include signatures using the SigHashAll sighash type. This allows validation
// to re-use previous hashing computation, reducing the complexity of validating
// SigHashAll inputs from O(N^2) to O(N).
func (t Transaction) calculateHashSequence(hashType uint32) ([]byte, error) {
	if !(hashType&ZEC_SigHashAnyOneCanPay == 0 &&
		hashType&sighashMask != ZEC_SigHashSingle &&
		hashType&sighashMask != ZEC_SigHashNone) {
		return get32ZeroHash(), nil
	}

	var b bytes.Buffer
	for _, in := range t.Vins {
		//var buf [4]byte
		//binary.LittleEndian.PutUint32(buf[:], in.)
		b.Write(in.sequence)
	}

	return blake2b(b.Bytes(), []byte(sequenceHashPersonalization))
}

// calculateHashOutputs computes a hash digest of all outputs created by
// the transaction encoded using the wire format. This single hash can be
// re-used when validating all inputs spending witness programs, which include
// signatures using the SigHashAll sighash type. This allows computation to be
// cached, reducing the total hashing complexity from O(N^2) to O(N).
func (t Transaction) calculateHashOutputs(hashType uint32) ([]byte, error) {
	if !(hashType&sighashMask != ZEC_SigHashSingle && hashType&sighashMask != ZEC_SigHashNone) {
		return get32ZeroHash(), nil
	}
	var b bytes.Buffer

	for _, out := range t.Vouts {
		b.Write(out.amount)

		b.Write(proto.EncodeVarint(uint64(len(out.lockScript))))

		b.Write(out.lockScript)
	}

	return blake2b(b.Bytes(), []byte(outputsHashPersonalization))
}

func blake2b(data, key []byte) (h []byte, err error) {
	bHash := blake2.New(&blake2.Config{
		Size:     32,
		Personal: key,
	})

	if _, err = bHash.Write(data); err != nil {
		return h, err
	}

	h = bHash.Sum(nil)
	return
}

func (t Transaction) encodeToBytesV4(index int, subScript []byte, amount uint64) ([]byte, error) {

	if t.Vins == nil || len(t.Vins) == 0 {
		return nil, errors.New("No input found in the transaction struct!")
	}

	if t.Vouts == nil || len(t.Vouts) == 0 {
		return nil, errors.New("No output found in the transaction struct!")
	}

	if t.Version == nil || len(t.Version) != 4 {
		return nil, errors.New("Invalid transaction version data!")
	}

	if t.LockTime == nil || len(t.LockTime) != 4 {
		return nil, errors.New("Invalid loack time data!")
	}

	hashType := ZEC_SigHashAll
	zeroBytes := [32]byte{} //uint32ToLittleEndianBytes(0)

	hashPrevouts, err := t.calculateHashPrevOuts(hashType)
	if err != nil {
		return nil, err
	}
	hashSequence, err := t.calculateHashSequence(hashType)
	if err != nil {
		return nil, err
	}
	hashOutputs, err := t.calculateHashOutputs(hashType)
	if err != nil {
		return nil, err
	}

	ret := []byte{}
	ret = append(ret, t.Version...) //1

	ret = append(ret, t.VersionGroupId...) //2

	ret = append(ret, hashPrevouts...) //3
	ret = append(ret, hashSequence...) //4
	ret = append(ret, hashOutputs...)  //5

	// << hashJoinSplits
	ret = append(ret, zeroBytes[:]...) //5

	// << hashShieldedSpends
	ret = append(ret, zeroBytes[:]...) //5

	// << hashShieldedOutputs
	ret = append(ret, zeroBytes[:]...) //5

	ret = append(ret, t.LockTime...) //7

	ret = append(ret, t.ExpiryHeight...) //8

	// << valueBalance
	ret = append(ret, uint64ToLittleEndianBytes(0)...)

	// << nHashType
	ret = append(ret, uint32ToLittleEndianBytes(hashType)...)
	// << prevout
	// Next, write the outpoint being spent.
	ret = append(ret, t.Vins[index].TxID...) //

	ret = append(ret, t.Vins[index].Vout...) //

	// << scriptCode
	// For p2wsh outputs, and future outputs, the script code is the
	// original script, with all code separators removed, serialized
	// with a var int length prefix.
	// wire.WriteVarBytes(&sigHash, 0, subScript)
	slen := uint64(len(subScript))
	ret = append(ret, proto.EncodeVarint(slen)...)
	ret = append(ret, subScript...)

	// << amount
	// Next, add the input amount, and sequence number of the input being
	// signed.
	ret = append(ret, uint64ToLittleEndianBytes(amount)...)

	// << nSequence
	ret = append(ret, t.Vins[index].sequence...)

	fmt.Println("me:::", index, ",,"+hex.EncodeToString(ret))

	var h []byte
	if h, err = blake2b(ret, sighashKey()); err != nil {
		return nil, err
	}

	return h, nil
}

func sighashKey() []byte {
	branchId := []byte{0xA6, 0x75, 0xff, 0xe9}
	//0xe9ff75a6
	return append([]byte(blake2BSighash), branchId...)
}

func (t Transaction) encodeToBytes(SegwitON bool) ([]byte, error) {
	if t.Vins == nil || len(t.Vins) == 0 {
		return nil, errors.New("No input found in the transaction struct!")
	}

	if t.Vouts == nil || len(t.Vouts) == 0 {
		return nil, errors.New("No output found in the transaction struct!")
	}

	if t.Version == nil || len(t.Version) != 4 {
		return nil, errors.New("Invalid transaction version data!")
	}

	if t.LockTime == nil || len(t.LockTime) != 4 {
		return nil, errors.New("Invalid loack time data!")
	}

	ret := []byte{}
	ret = append(ret, t.Version...) //1

	ret = append(ret, t.VersionGroupId...) //2

	//var hashPrevouts = this.getPrevoutHash(hashType)
	//var hashSequence = this.getSequenceHash(hashType)
	//var hashOutputs = this.getOutputsHash(hashType, inIndex)
	//hashJoinSplits := 0
	//hashShieldedSpends := 0
	//hashShieldedOutputs := 0
	//
	//bufferWriter.writeSlice(hashPrevouts)
	//bufferWriter.writeSlice(hashSequence)
	//bufferWriter.writeSlice(hashOutputs)
	//bufferWriter.writeSlice(hashJoinSplits)

	if t.Witness {
		ret = append(ret, SegWitSymbol, SegWitVersion)
	}

	ret = append(ret, byte(len(t.Vins))) //3
	for _, in := range t.Vins {
		//inBytes, err := in.toBytes(SegwitON)
		//if err != nil {
		//	return nil, err
		//}
		//ret = append(ret, inBytes...)//4

		ret = append(ret, in.TxID...)
		ret = append(ret, in.Vout...)
		ret = append(ret, byte(len(in.scriptSig)))
		ret = append(ret, in.scriptSig...)
		ret = append(ret, in.sequence...)

	}

	ret = append(ret, byte(len(t.Vouts))) //5

	for _, out := range t.Vouts {
		outBytes, err := out.toBytes()
		if err != nil {
			return nil, err
		}
		ret = append(ret, outBytes...) //6
	}

	if t.Witness {
		for _, in := range t.Vins {
			swBytes, err := in.toSegwitBytes()
			if err != nil {
				return nil, err
			}
			ret = append(ret, swBytes...)
		}
	}
	ret = append(ret, t.LockTime...) //7

	ret = append(ret, t.ExpiryHeight...) //8

	//9
	ret = append(ret, uint64ToLittleEndianBytes(0)...)

	//10
	ret = append(ret, proto.EncodeVarint(0)...)

	//11
	ret = append(ret, proto.EncodeVarint(0)...)

	//12
	ret = append(ret, proto.EncodeVarint(0)...)

	return ret, nil
}

func DecodeRawTransaction(txBytes []byte, SegwitON bool) (*Transaction, error) {
	limit := len(txBytes)

	if limit == 0 {
		return nil, errors.New("Invalid transaction data!")
	}

	var rawTx Transaction

	index := 0

	if index+4 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}

	rawTx.Version = txBytes[index : index+4]
	index += 4

	if littleEndianBytesToUint32(rawTx.Version) != DefaultTxVersion|(1<<31) {
		return nil, errors.New("Only transaction version 2 is supported right now!")
	}

	if index+4 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}

	rawTx.VersionGroupId = txBytes[index : index+4]
	index += 4
	if littleEndianBytesToUint32(rawTx.VersionGroupId) != nVersionGroupId {
		return nil, errors.New("Only transaction VersionGroupID 2 is supported right now!")
	}

	if index+2 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}
	if txBytes[index] == SegWitSymbol {
		if txBytes[index+1] != SegWitVersion {
			return nil, errors.New("Invalid witness symbol!")
		}
		rawTx.Witness = true
		index += 2
	}

	if index+1 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}
	numOfVins := txBytes[index]
	index++
	if numOfVins == 0 {
		return nil, errors.New("Invalid transaction data!")
	}

	for i := byte(0); i < numOfVins; i++ {
		var tmpTxIn TxIn

		if index+32 > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		tmpTxIn.TxID = txBytes[index : index+32]
		index += 32

		if index+4 > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		tmpTxIn.Vout = txBytes[index : index+4]
		index += 4

		if index+1 > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		scriptLen := int(txBytes[index])
		index++

		if scriptLen == 0 {
			tmpTxIn.scriptPub = nil
			tmpTxIn.scriptSig = nil
			if rawTx.Witness {
				tmpTxIn.inType = TypeBech32
			} else {
				tmpTxIn.inType = TypeEmpty
			}
		} else if scriptLen == 0x17 {
			if !rawTx.Witness {
				return nil, errors.New("Invalid transaction data!")
			}
			tmpTxIn.inType = TypeP2WPKH
			if index+scriptLen > limit {
				return nil, errors.New("Invalid transaction data length!")
			}
			tmpTxIn.scriptPub = txBytes[index : index+scriptLen]
			index += int(scriptLen)
		} else if scriptLen == 0x23 {
			if !rawTx.Witness {
				return nil, errors.New("Invalid transaction data!")
			}
			tmpTxIn.inType = TypeMultiSig
			if index+scriptLen > limit {
				return nil, errors.New("Invalid transaction data length!")
			}
			tmpTxIn.scriptPub = append([]byte{0x23}, txBytes[index:index+scriptLen]...)
			index += int(scriptLen)
		} else if scriptLen <= 0x6C {
			tmpTxIn.inType = TypeP2PKH
			if index+scriptLen > limit {
				return nil, errors.New("Invalid transaction data length!")
			}
			tmpTxIn.scriptSig = txBytes[index : index+scriptLen]
			index += int(scriptLen)
		} else {
			if rawTx.Witness {
				return nil, errors.New("Invalid transaction data!")
			}
			tmpTxIn.inType = TypeMultiSig
			if scriptLen == 0xFD {
				if index+2 > limit {
					return nil, errors.New("Invalid transaction data length!")
				}
				scriptLen = int(littleEndianBytesToUint16(txBytes[index : index+2]))
				if index+scriptLen > limit {
					return nil, errors.New("Invalid transaction data length!")
				}
				tmpTxIn.scriptMulti = append([]byte{0xFD}, txBytes[index:index+scriptLen+2]...)
				index += scriptLen + 2
			} else if scriptLen > 0xFD {
				return nil, errors.New("Invalid transaction data!")
			} else {
				if index+scriptLen > limit {
					return nil, errors.New("Invalid transaction data length!")
				}
				tmpTxIn.scriptMulti = append(tmpTxIn.scriptMulti, txBytes[index:index+scriptLen]...)
				index += scriptLen
			}
		}

		tmpTxIn.sequence = txBytes[index : index+4]
		index += 4
		rawTx.Vins = append(rawTx.Vins, tmpTxIn)
	}

	if index+1 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}

	numOfVouts := txBytes[index]
	index++
	if numOfVouts == 0 {
		return nil, errors.New("Invalid transaction data!")
	}

	for i := byte(0); i < numOfVouts; i++ {
		var tmpTxOut TxOut

		if index+8 > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		tmpTxOut.amount = txBytes[index : index+8]
		index += 8

		if index+1 > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		lockScriptLen := txBytes[index]
		index++

		if lockScriptLen == 0 {
			return nil, errors.New("Invalid transaction data!")
		}

		if index+int(lockScriptLen) > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		tmpTxOut.lockScript = txBytes[index : index+int(lockScriptLen)]
		index += int(lockScriptLen)

		rawTx.Vouts = append(rawTx.Vouts, tmpTxOut)
	}

	if rawTx.Witness {
		for i := byte(0); i < numOfVins; i++ {
			if index+1 > limit {
				return nil, errors.New("Invalid transaction data length!")
			}
			if rawTx.Vins[i].inType == TypeP2PKH {
				if txBytes[index] != 0x00 {
					return nil, errors.New("Invalid transaction data!")
				}
				index++
			} else if rawTx.Vins[i].inType == TypeP2WPKH || rawTx.Vins[i].inType == TypeBech32 {
				if txBytes[index] != 0x02 {
					return nil, errors.New("Invalid transaction data!")
				}
				index++
				if index+1 > limit {
					return nil, errors.New("Invalid transaction data length!")
				}
				sigLen := int(txBytes[index])
				if index+sigLen+35 > limit {
					return nil, errors.New("Invalid transaction data length!")
				}
				rawTx.Vins[i].scriptSig = txBytes[index : index+sigLen+35]

				index += sigLen + 35
			} else if rawTx.Vins[i].inType == TypeMultiSig {
				if !SegwitON {
					return nil, errors.New("Invalid transaction data!")
				}
				if txBytes[index] != 0x04 {
					return nil, errors.New("Invalid transaction data!")
				}
				index++
				if !SegwitON {
					scriptLen := int(txBytes[index])
					if scriptLen == 0xFD {
						if index+2 > limit {
							return nil, errors.New("Invalid transaction data!")
						}
						scriptLen = int(littleEndianBytesToUint16(txBytes[index+1 : index+3]))
						index += 3
					} else if scriptLen > 0xFD {
						return nil, errors.New("Invalid transaction data!")
					} else {
						index++
					}
				}

				if txBytes[index] != 0x00 {
					return nil, errors.New("Invalid transaction data!")
				}
				rawTx.Vins[i].scriptMulti = []byte{0x00}
				index++

				for {
					if index+2 > limit {
						return nil, errors.New("Invalid transaction data!")
					}
					if txBytes[index+1] != 0x30 {
						break
					}
					sigLen := txBytes[index]
					rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, sigLen)
					index++
					if index+int(sigLen) > limit {
						return nil, errors.New("Invalid transaction data!")
					}
					rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index:index+int(sigLen)]...)
					index += int(sigLen)
				}
				if index+1 > limit {
					return nil, errors.New("Invalid transaction data!")
				}
				redeemLen := 0
				if !SegwitON {
					if txBytes[index] == OpPushData1 {
						rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, OpPushData1)
						index++
						if index+1 > limit {
							return nil, errors.New("Invalid transaction data!")
						}
						redeemLen = int(txBytes[index])
						rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index])
						index++
					} else if txBytes[index] == OpPushData2 {
						rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, OpPushData2)
						index++
						if index+2 > limit {
							return nil, errors.New("Invalid transaction data!")
						}
						redeemLen = int(littleEndianBytesToUint16(txBytes[index : index+2]))
						rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index:index+2]...)
						index += 2
					} else {
						redeemLen = int(txBytes[index])
						rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index])
						index++
					}
				} else {
					redeemLen = int(txBytes[index])
					rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index])
					index++
				}

				if index+int(redeemLen) > limit {
					return nil, errors.New("Invalid transaction data!")
				}
				if txBytes[index+int(redeemLen)-1] != OpCheckMultiSig {
					return nil, errors.New("Invalid transaction data!")
				}
				rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index:index+int(redeemLen)]...)
				index += redeemLen
			}
		}
	}

	//7
	if index+4 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}
	rawTx.LockTime = txBytes[index : index+4]
	index += 4

	//8
	if index+4 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}
	rawTx.ExpiryHeight = txBytes[index : index+4]
	index += 4

	//if index != limit {
	//	return nil, errors.New("Too much transaction data!")
	//}
	return &rawTx, nil
}

func isSegwit(unlockData []TxUnlock, SegwitON bool) (bool, error) {
	if unlockData == nil || len(unlockData) == 0 {
		return false, errors.New("No lockscript or redeem script found!")
	}
	for _, u := range unlockData {
		_, _, inType, err := checkScriptType(u.LockScript, u.RedeemScript)
		if err != nil {
			return false, err
		}

		if inType == TypeP2WPKH || inType == TypeBech32 || (inType == TypeMultiSig && SegwitON) {
			return true, nil
		}
	}
	return false, nil
}

func (t Transaction) cloneEmpty() Transaction {
	var ret Transaction
	ret.Version = append(ret.Version, t.Version...)
	ret.VersionGroupId = append(ret.VersionGroupId, t.VersionGroupId...)
	ret.Vins = append(ret.Vins, t.Vins...)
	ret.Vouts = append(ret.Vouts, t.Vouts...)
	ret.LockTime = append(ret.LockTime, t.LockTime...)
	ret.ExpiryHeight = append(ret.ExpiryHeight, t.ExpiryHeight...)
	ret.Witness = false
	for i := 0; i < len(ret.Vins); i++ {
		ret.Vins[i].setEmpty()
	}
	return ret
}

package acalaTransaction

import "math/big"

type TxStruct struct {
	SenderPubkey       string `json:"sender_pubkey"`
	RecipientPubkey    string `json:"recipient_pubkey"`
	Amount             *big.Int `json:"amount"`
	Nonce 			   uint64 `json:"nonce"`
	Fee                *big.Int `json:"fee"`
	BlockHeight        uint64 `json:"block_height"`
	BlockHash          string `json:"block_hash"`
	GenesisHash        string `json:"genesis_hash"`
	SpecVersion        uint32 `json:"spec_version"`
	TxVersion          uint32 `json:"txVersion"`
}


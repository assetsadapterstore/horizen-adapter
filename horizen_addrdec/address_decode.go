package horizen_addrdec

import (
	"github.com/blocktree/go-owcdrivers/addressEncoder"
)

const (
	btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

var (
	ZEN_mainnetAddressP2PKH         = addressEncoder.AddressType{EncodeType: "base58", Alphabet: btcAlphabet, ChecksumType: "doubleSHA256", HashType: "h160", HashLen: 20, Prefix: []byte{0x20,0x89}, Suffix: nil}
	ZEN_testnetAddressP2PKH         = addressEncoder.AddressType{EncodeType: "base58", Alphabet: btcAlphabet, ChecksumType: "doubleSHA256", HashType: "h160", HashLen: 20, Prefix: []byte{0x20,0x98}, Suffix: nil}
	ZEN_mainnetPrivateWIFCompressed = addressEncoder.AddressType{EncodeType: "base58", Alphabet: btcAlphabet, ChecksumType: "doubleSHA256", HashType: "", HashLen: 32, Prefix: []byte{0x80}, Suffix: []byte{0x01}}
	ZEN_testnetPrivateWIFCompressed = addressEncoder.AddressType{EncodeType: "base58", Alphabet: btcAlphabet, ChecksumType: "doubleSHA256", HashType: "", HashLen: 32, Prefix: []byte{0xEF}, Suffix: []byte{0x01}}
	ZEN_mainnetAddressP2SH          = addressEncoder.AddressType{EncodeType: "base58", Alphabet: btcAlphabet, ChecksumType: "doubleSHA256", HashType: "h160", HashLen: 20, Prefix: []byte{0x20,0x96}, Suffix: nil}
	ZEN_testnetAddressP2SH          = addressEncoder.AddressType{EncodeType: "base58", Alphabet: btcAlphabet, ChecksumType: "doubleSHA256", HashType: "h160", HashLen: 20, Prefix: []byte{0x20,0x92}, Suffix: nil}
	//ZEN_mainnetAddressBech32V0      = addressEncoder.AddressType{"bech32", btcAlphabet, "btx", "h160", 20, nil, nil}
	//ZEN_testnetAddressBech32V0      = addressEncoder.AddressType{"bech32", btcAlphabet, "tb", "h160", 20, nil, nil}

	Default = AddressDecoderV2{}
)

//AddressDecoderV2
type AddressDecoderV2 struct {
	IsTestNet bool
}

//AddressDecode 地址解析
func (dec *AddressDecoderV2) AddressDecode(addr string, opts ...interface{}) ([]byte, error) {

	cfg := ZEN_mainnetAddressP2PKH
	if dec.IsTestNet {
		cfg = ZEN_testnetAddressP2PKH
	}

	if len(opts) > 0 {
		for _, opt := range opts {
			if at, ok := opt.(addressEncoder.AddressType); ok {
				cfg = at
			}
		}
	}

	return addressEncoder.AddressDecode(addr, cfg)
}

//AddressEncode 地址编码
func (dec *AddressDecoderV2) AddressEncode(hash []byte, opts ...interface{}) (string, error) {

	cfg := ZEN_mainnetAddressP2PKH
	if dec.IsTestNet {
		cfg = ZEN_testnetAddressP2PKH
	}

	if len(opts) > 0 {
		for _, opt := range opts {
			if at, ok := opt.(addressEncoder.AddressType); ok {
				cfg = at
			}
		}
	}

	address := addressEncoder.AddressEncode(hash, cfg)
	return address, nil
}

package chain

import (
	"github.com/pkg/errors"
	"github.com/vedhavyas/go-subkey"
	"github.com/vedhavyas/go-subkey/sr25519"
)

func ParsingPublickey(address string) ([]byte, error) {
	_, pubkey, err := subkey.SS58Decode(address)
	return pubkey, errors.Wrap(err, "parse publick key error")
}

func EncodePubkey(pubkey []byte, format uint16) string {
	return subkey.SS58Encode(pubkey, format)
}

func SignedSR25519WithMnemonic(mnemonic string, msg []byte) ([]byte, error) {

	pri, err := sr25519.Scheme{}.FromPhrase(mnemonic, "")
	if err != nil {
		return nil, errors.New("invalid mnemonic")
	}
	return pri.Sign(msg)
}

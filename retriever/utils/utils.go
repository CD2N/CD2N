package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/base58"
	"github.com/mholt/archiver"
	"github.com/vedhavyas/go-subkey/sr25519"
	"golang.org/x/crypto/blake2b"

	ecies "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

const (
	ARCHIVER_FORMAT_ZIP   = "zip"
	ARCHIVER_FORMAT_TAR   = "tar"
	ARCHIVER_FORMAT_TARGZ = "tar.gz"

	UNNAMED_FILENAME = "Unnamed"
)

var (
	SSPrefix        = []byte{0x53, 0x53, 0x35, 0x38, 0x50, 0x52, 0x45}
	SubstratePrefix = []byte{0x2a}
	CessPrefix      = []byte{0x50, 0xac}
)

func ParsingPublickey(address string) ([]byte, error) {
	err := VerityAddress(address, CessPrefix)
	if err != nil {
		err := VerityAddress(address, SubstratePrefix)
		if err != nil {
			return nil, errors.New("invalid account")
		}
		data := base58.Decode(address)
		if len(data) != (34 + len(SubstratePrefix)) {
			return nil, errors.New("public key decoding failed")
		}
		return data[len(SubstratePrefix) : len(data)-2], nil
	} else {
		data := base58.Decode(address)
		if len(data) != (34 + len(CessPrefix)) {
			return nil, errors.New("public key decoding failed")
		}
		return data[len(CessPrefix) : len(data)-2], nil
	}
}

func EncodePublicKeyAsSubstrateAccount(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", errors.New("invalid public key")
	}
	payload := appendBytes(SubstratePrefix, publicKey)
	input := appendBytes(SSPrefix, payload)
	ck := blake2b.Sum512(input)
	checkum := ck[:2]
	address := base58.Encode(appendBytes(payload, checkum))
	if address == "" {
		return address, errors.New("public key encoding failed")
	}
	return address, nil
}

func EncodePublicKeyAsCessAccount(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", errors.New("invalid public key")
	}
	payload := appendBytes(CessPrefix, publicKey)
	input := appendBytes(SSPrefix, payload)
	ck := blake2b.Sum512(input)
	checkum := ck[:2]
	address := base58.Encode(appendBytes(payload, checkum))
	if address == "" {
		return address, errors.New("public key encoding failed")
	}
	return address, nil
}

func appendBytes(data1, data2 []byte) []byte {
	if data2 == nil {
		return data1
	}
	return append(data1, data2...)
}

func VerityAddress(address string, prefix []byte) error {
	decodeBytes := base58.Decode(address)
	if len(decodeBytes) != (34 + len(prefix)) {
		return errors.New("public key decoding failed")
	}
	if decodeBytes[0] != prefix[0] {
		return errors.New("invalid account prefix")
	}
	pub := decodeBytes[len(prefix) : len(decodeBytes)-2]

	data := append(prefix, pub...)
	input := append(SSPrefix, data...)
	ck := blake2b.Sum512(input)
	checkSum := ck[:2]
	for i := 0; i < 2; i++ {
		if checkSum[i] != decodeBytes[32+len(prefix)+i] {
			return errors.New("invalid account")
		}
	}
	if len(pub) != 32 {
		return errors.New("invalid account public key")
	}
	return nil
}

func SignedSR25519WithMnemonic(mnemonic string, msg string) ([]byte, error) {

	pri, err := sr25519.Scheme{}.FromPhrase(mnemonic, "")
	if err != nil {
		return nil, errors.New("invalid mnemonic")
	}
	return pri.Sign([]byte(msg))
}

func VerifySR25519WithPublickey(msg, sign, pubkey []byte) (bool, error) {
	public, err := sr25519.Scheme{}.FromPublicKey(pubkey)
	if err != nil {
		return false, err
	}
	ok := public.Verify(msg, sign)
	return ok, err
}

type Archiver interface {
	Archive(files []string, dest string) error
	Unarchive(src, dest string) error
	Extract(src string, target string, dest string) error
	Close() error
}

func NewArchiver(archiveFormat string) (Archiver, error) {
	var ar Archiver
	switch archiveFormat {
	case ARCHIVER_FORMAT_ZIP:
		ar = archiver.NewZip()
	case ARCHIVER_FORMAT_TAR:
		ar = archiver.NewTar()

	case ARCHIVER_FORMAT_TARGZ:
		ar = archiver.NewTarGz()
	default:
		err := errors.New("unsupported archive format")
		return nil, errors.Wrap(err, "compress data error")
	}
	return ar, nil
}

func CalcSha256Hash(datas ...[]byte) []byte {
	hash := sha256.New()
	for _, data := range datas {
		hash.Write(data)
	}
	return hash.Sum(nil)
}

func GetRandomBytes() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

func FillRandData(data []byte) error {
	var (
		buf []byte
		err error
	)
	for i := 0; i < len(data); i++ {
		idx := i % 32
		if idx == 0 {
			buf, err = GetRandomBytes()
			if err != nil {
				return err
			}
		}
		data[i] = buf[idx]
	}
	return nil
}

func VerifySecp256k1Sign(pubkey, data, sign []byte) bool {

	hash := crypto.Keccak256Hash(data)
	return crypto.VerifySignature(
		pubkey,
		hash.Bytes(), sign[:len(sign)-1],
	)
}

func SignWithSecp256k1PrivateKey(sk *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := crypto.Keccak256Hash(data)
	sign, err := crypto.Sign(hash.Bytes(), sk)
	if err != nil {
		return nil, err
	}
	return sign, nil
}

func GetAESKeyEncryptedWithECDH(sk *ecies.PrivateKey, pubkey []byte) ([]byte, []byte, error) {
	var err error

	pk, err := ecies.NewPublicKeyFromBytes(pubkey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
	}
	ecdhKey, err := sk.ECDH(pk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
	}
	hashKey := sha256.Sum256(ecdhKey)
	return hashKey[:], sk.PublicKey.Bytes(true), nil
}

func AesEncrypt(data, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return ciphertext, nil
}

func AesDecrypt(data, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func EncryptFile(fpath string, key, nonce []byte) (string, error) {
	var (
		newPath string
		err     error
	)
	f, err := os.Open(fpath)
	if err != nil {
		return newPath, errors.Wrap(err, "encrypt file with aes error")
	}

	newPath = filepath.Join(filepath.Dir(fpath), hex.EncodeToString([]byte(fpath)))
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return newPath, errors.Wrap(err, "encrypt file with aes error")
	}
	data, err = AesEncrypt(data, key, nonce)
	if err != nil {
		return newPath, errors.Wrap(err, "encrypt file with aes error")
	}
	f, err = os.Create(newPath)
	if err != nil {
		return newPath, errors.Wrap(err, "encrypt file with aes error")
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return newPath, errors.Wrap(err, "encrypt file with aes error")
	}
	return newPath, nil
}

func Remove0x(hex string) string {
	if strings.HasPrefix(strings.ToLower(hex), "0x") {
		return hex[2:]
	}
	return hex
}

func CatNamePath(name, path string) string {
	return fmt.Sprintf("%s-=+>%s", name, path)
}

func SplitNamePath(namepath string) (string, string) {
	strs := strings.Split(namepath, "-=+>")
	if len(strs) != 2 {
		return UNNAMED_FILENAME, strs[len(strs)-1]
	}
	return strs[0], strs[1]
}

func ExtraPath(fpath string) string {
	n, p := SplitNamePath(fpath)
	if strings.Contains(n, UNNAMED_FILENAME) {
		p = fpath
	}
	return p
}

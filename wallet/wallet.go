package wallet

//https://pkg.go.dev/crypto/ecdsa@go1.21.3
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	_ "github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
	_ "golang.org/x/crypto/ripemd160"
)

type Wallet struct {
	privateKey        *ecdsa.PrivateKey
	publicKey         *ecdsa.PublicKey
	blockchainAddress string
}

func NewWallet() *Wallet {
	// https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	// Address を短くするために、Base58 というアルゴリズムを使っている。
	// 1. Create ECDSA private key (32 bytes) pulic key (64 bytes)
	w := new(Wallet)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	w.privateKey = privateKey
	w.publicKey = &privateKey.PublicKey
	// 2. Perform SHA-256 hashing on the public key (32 bytes).
	h2 := sha256.New()
	h2.Write(w.publicKey.X.Bytes())
	h2.Write(w.publicKey.Y.Bytes())
	digest2 := h2.Sum(nil)
	// 3. Perform RIPEMD-160 hashing on the result of SHA-256 (20 bytes).
	h3 := ripemd160.New()
	h3.Write(digest2)
	digest3 := h3.Sum(nil)
	// 4. Add version byte in front of RIPEMD-160 hash (0x00 for Main Network).
	// [SHA-256 (20 bytes)] + [0x00 (1 bytes)] = 21bytes
	vd4 := make([]byte, 21)
	vd4[0] = 0x00
	copy(vd4[1:], digest3[:])
	// 5. Perform SHA-256 hash on the extended RIPEMD-160 result.
	h5 := sha256.New()
	h5.Write(vd4)
	digest5 := h5.Sum(nil)
	// 6. Perform SHA-256 hash on the result of the previous SHA-256 hash.
	h6 := sha256.New()
	h6.Write(digest5)
	digest6 := h5.Sum(nil)
	// 7. Take the first 4 bytes of the second SHA-256 hash for checksum.
	chsum := digest6[:4]
	// 8. Add the 4 checksum bytes from 7 at the end of extended RIPEMD-160 hash from 4 (25 bytes).
	//[vd4 (21byte] + [chsum (4byte)] = 25bytes
	dc8 := make([]byte, 25)
	copy(dc8[:21], vd4[:])
	copy(dc8[21:], chsum[:])
	// 9. Convert the result from a byte string into base58.
	address := base58.Encode(dc8)
	w.blockchainAddress = address

	return w
}

func (w *Wallet) PrivateKey() *ecdsa.PrivateKey {
	return w.privateKey
}

func (w *Wallet) PrivateKeyStr() string {
	return fmt.Sprintf("%x", w.privateKey.D.Bytes())
}

func (w *Wallet) PublicKey() *ecdsa.PublicKey {
	return w.publicKey
}

func (w *Wallet) PublicKeyStr() string {
	return fmt.Sprintf("%x%x", w.publicKey.X.Bytes(), w.publicKey.Y.Bytes())
}

func (w *Wallet) BlockchainAddress() string {
	// プライペーとな変数にすることで書き換えを防ぎ、ブロックチェーンアドレスを保護する。
	// ブロックチェーンアドレスを呼び出すときは、このメソッドを使う。
	return w.blockchainAddress
}

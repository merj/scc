package scc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"time"

	"github.com/shengdoushi/base58"
)

// Generate using: hf merj.pub
const ckh = ""

type Sec struct {
	D *big.Int
}

type Pub struct {
	X, Y *big.Int
}

type Sig struct {
	R, S *big.Int
}

type Con struct {
	A, B time.Time
	Hash []byte
	Args []string
}

type ConSig struct {
	Con Con
	Sig Sig
}

type ConSigPub struct {
	Con Con
	Sig Sig
	Pub Pub
}

func Encode(v interface{}) ([]byte, error) {
	b, err := asn1.Marshal(v)
	if err != nil {
		return nil, err
	}
	b = []byte(base58.Encode(b, base58.IPFSAlphabet))
	return b, nil
}

func Decode(v interface{}, b []byte) error {
	b, err := base58.Decode(string(b), base58.IPFSAlphabet)
	if err != nil {
		return err
	}
	_, err = asn1.Unmarshal(b, v)
	if err != nil {
		return err
	}
	return nil
}

func Sign(b []byte, sec *Sec) (*Sig, error) {
	var k ecdsa.PrivateKey
	k.Curve = elliptic.P256()
	k.D = sec.D
	hf := sha256.New()
	_, err := hf.Write(b)
	if err != nil {
		return nil, err
	}
	h := hf.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, &k, h)
	if err != nil {
		return nil, err
	}
	var sig Sig
	sig.R = r
	sig.S = s
	return &sig, nil
}

func Verify(b []byte, sig *Sig, pub *Pub) (bool, error) {
	var k ecdsa.PublicKey
	k.Curve = elliptic.P256()
	k.X = pub.X
	k.Y = pub.Y
	hf := sha256.New()
	_, err := hf.Write(b)
	if err != nil {
		return false, err
	}
	h := hf.Sum(nil)
	return ecdsa.Verify(&k, h, sig.R, sig.S), nil
}

func Sha256(b []byte) ([]byte, error) {
	hf := sha256.New()
	_, err := hf.Write(b)
	if err != nil {
		return nil, err
	}
	h := hf.Sum(nil)
	return h, nil
}

func EncodeFile(v interface{}, fn string) error {
	b, err := Encode(v)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fn, b, 0600)
}

func DecodeFile(v interface{}, fn string) error {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return err
	}
	return Decode(v, b)
}

func SignFile(fn string, sec *Sec) (*Sig, error) {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	sig, err := Sign(b, sec)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func VerifyFile(fn string, sig *Sig, pub *Pub) (bool, error) {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return false, err
	}
	ok, err := Verify(b, sig, pub)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func Sha256File(fn string) ([]byte, error) {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	h, err := Sha256(b)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func Dprintf(format string, a ...interface{}) {
	if _, ok := os.LookupEnv("DEBUG"); ok {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}

func Authorize() (*Con, error) {
	kpn, ok := os.LookupEnv("SCCCK")
	if !ok {
		return nil, errors.New("SCCCK is not set")
	}

	pkfn := fmt.Sprintf("%s.pub", kpn)
	b, err := ioutil.ReadFile(pkfn)
	if err != nil {
		return nil, err
	}

	h, err := Sha256(b)
	if err != nil {
		return nil, err
	}
	pkh := base58.Encode(h, base58.IPFSAlphabet)

	if ckh != pkh {
		return nil, errors.New("contract required")
	}

	var pub Pub
	err = Decode(&pub, b)
	if err != nil {
		return nil, err
	}

	efn, err := os.Executable()
	if err != nil {
		return nil, err
	}

	cn, ok := os.LookupEnv("SCCCN")
	if !ok {
		cn = path.Base(efn)
	}

	sfn := fmt.Sprintf("%s.con.sig", cn)
	var sig Sig
	err = DecodeFile(&sig, sfn)
	if err != nil {
		return nil, err
	}

	cfn := fmt.Sprintf("%s.con", cn)
	b, err = ioutil.ReadFile(cfn)
	if err != nil {
		return nil, err
	}

	ok, err = Verify(b, &sig, &pub)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("contract required")
	}

	var con Con
	err = Decode(&con, b)
	if err != nil {
		return nil, err
	}

	n := time.Now()
	if con.A.After(n) || n.After(con.B) {
		return nil, errors.New("contract required")
	}

	chs := base58.Encode(con.Hash, base58.IPFSAlphabet)

	h, err = Sha256File(efn)
	if err != nil {
		return nil, err
	}
	ehs := base58.Encode(h, base58.IPFSAlphabet)

	if chs != ehs {
		return nil, errors.New("contract required")
	}

	return &con, nil
}

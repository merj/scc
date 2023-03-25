package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"path"

	"github.com/merj/scc"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s k\n", path.Base(os.Args[0]))
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		usage()
	}

	kpn := os.Args[1]

	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(3)
	}
	pk := &sk.PublicKey

	skfn := fmt.Sprintf("%s.sec", kpn)
	var sec scc.Sec
	sec.D = sk.D
	err = scc.EncodeFile(sec, skfn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(4)
	}

	pkfn := fmt.Sprintf("%s.pub", kpn)
	var pub scc.Pub
	pub.X = pk.X
	pub.Y = pk.Y
	err = scc.EncodeFile(pub, pkfn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(5)
	}
}

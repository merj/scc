package main

import (
	"fmt"
	"os"
	"path"

	"github.com/shengdoushi/base58"
	"github.com/merj/scc"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s f\n", path.Base(os.Args[0]))
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		usage()
	}

	fn := os.Args[1]

	h, err := scc.Sha256File(fn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(3)
	}
	hs := base58.Encode(h, base58.IPFSAlphabet)

	fmt.Println(hs)
}

package main

import (
	"fmt"
	"os"
	"path"

	"github.com/merj/scc"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s f k\n", path.Base(os.Args[0]))
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 {
		usage()
	}

	fn := os.Args[1]
	kpn := os.Args[2]

	pkfn := fmt.Sprintf("%s.pub", kpn)
	var pub scc.Pub
	err := scc.DecodeFile(&pub, pkfn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(3)
	}

	sfn := fmt.Sprintf("%s.sig", fn)
	var sig scc.Sig
	err = scc.DecodeFile(&sig, sfn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(4)
	}

	ok, err := scc.VerifyFile(fn, &sig, &pub)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(5)
	}

	if ok {
		os.Exit(0)
	} else {
		os.Exit(6)
	}
}

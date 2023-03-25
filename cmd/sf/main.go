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

	skfn := fmt.Sprintf("%s.sec", kpn)
	var sec scc.Sec
	err := scc.DecodeFile(&sec, skfn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(3)
	}

	sig, err := scc.SignFile(fn, &sec)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(4)
	}

	sfn := fmt.Sprintf("%s.sig", fn)
	err = scc.EncodeFile(*sig, sfn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(5)
	}
}

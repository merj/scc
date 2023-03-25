package main

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/shengdoushi/base58"
	"github.com/merj/scc"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s c\n", path.Base(os.Args[0]))
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		usage()
	}

	cn := os.Args[1]

	cfn := fmt.Sprintf("%s.con", cn)
	var con scc.Con
	err := scc.DecodeFile(&con, cfn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(3)
	}

	hs := base58.Encode(con.Hash, base58.IPFSAlphabet)

	fmt.Printf("%s\n%s\n%s\n%s\n",
		con.A.Format(time.RFC3339),
		con.B.Format(time.RFC3339),
		hs,
		strings.Join(con.Args, " "))
}

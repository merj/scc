package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/shengdoushi/base58"
	"github.com/merj/scc"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s t e ...\n", path.Base(os.Args[0]))
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 {
		usage()
	}

	t, err := strconv.ParseInt(os.Args[1], 10, 32)
	if err != nil || t < 3 {
		usage()
	}

	efn := os.Args[2]

	ta := time.Now()
	tb := ta.Add(time.Duration(t) * time.Second)

	h, err := scc.Sha256File(efn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(3)
	}

	var con scc.Con
	con.A = ta
	con.B = tb
	con.Hash = h
	con.Args = os.Args[2:]

	b, err := scc.Encode(con)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(3)
	}

	h, err = scc.Sha256(b)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(4)
	}
	chs := base58.Encode(h, base58.IPFSAlphabet)

	cfn := fmt.Sprintf("%s.con", chs)
	err = ioutil.WriteFile(cfn, b, 0600)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(5)
	}

	fmt.Println(chs)
}

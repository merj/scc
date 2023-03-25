package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"

	"github.com/merj/scc"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s c k a\n", path.Base(os.Args[0]))
	os.Exit(1)
}

func main() {
	if len(os.Args) != 4 {
		usage()
	}

	cn := os.Args[1]
	kpn := os.Args[2]
	a := os.Args[3]

	cfn := fmt.Sprintf("%s.con", cn)
	b, err := ioutil.ReadFile(cfn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(3)
	}

	var con scc.Con
	err = scc.Decode(&con, b)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(3)
	}

	skfn := fmt.Sprintf("%s.sec", kpn)
	var sec scc.Sec
	err = scc.DecodeFile(&sec, skfn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(4)
	}

	sig, err := scc.Sign(b, &sec)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(5)
	}

	pkfn := fmt.Sprintf("%s.pub", kpn)
	var pub scc.Pub
	err = scc.DecodeFile(&pub, pkfn)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(6)
	}

	var consig scc.ConSigPub
	consig.Con = con
	consig.Sig = *sig
	consig.Pub = pub
	b, err = scc.Encode(consig)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(7)
	}

	r, err := http.Post(a, "text/plain", bytes.NewBuffer(b))
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(8)
	}

	sfn := fmt.Sprintf("%s.con.sig", cn)
	sf, err := os.OpenFile(sfn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(9)
	}
	defer sf.Close()
	_, err = io.Copy(sf, r.Body)
	if err != nil {
		scc.Dprintf("%s\n", err)
		os.Exit(9)
	}
}

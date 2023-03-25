package main

import (
	"fmt"
	"io/ioutil"
	"log/syslog"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"path"

	"github.com/shengdoushi/base58"
	"github.com/merj/scc"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s k a d\n", path.Base(os.Args[0]))
	os.Exit(1)
}

func main() {
	if len(os.Args) != 4 {
		usage()
	}

	kpn := os.Args[1]
	a := os.Args[2]
	dn := os.Args[3]

	skfn := fmt.Sprintf("%s.sec", kpn)
	var sec scc.Sec
	err := scc.DecodeFile(&sec, skfn)
	if err != nil {
		os.Exit(3)
	}

	logger, err := syslog.New(syslog.LOG_ERR, "sccd")
	if err != nil {
		os.Exit(4)
	}
	defer logger.Close()

	handler := http.NewServeMux()

	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logger.Alert(err.Error())
			return
		}

		var consig scc.ConSigPub
		err = scc.Decode(&consig, b)
		if err != nil {
			logger.Debug(err.Error())
			return
		}

		b, err = scc.Encode(consig.Pub)
		if err != nil {
			logger.Debug(err.Error())
			return
		}
		h, err := scc.Sha256(b)
		if err != nil {
			return
		}
		pkhs := base58.Encode(h, base58.IPFSAlphabet)

		pkfn := path.Join(dn, fmt.Sprintf("%s.pub", pkhs))

		if _, err := os.Stat(pkfn); os.IsNotExist(err) {
			return
		}

		var pub scc.Pub
		err = scc.DecodeFile(&pub, pkfn)
		if err != nil {
			logger.Debug(err.Error())
			return
		}

		b, err = scc.Encode(consig.Con)
		if err != nil {
			logger.Debug(err.Error())
			return
		}
		ok, err := scc.Verify(b, &consig.Sig, &pub)
		if err != nil {
			logger.Debug(err.Error())
			return
		}
		if !ok {
			return
		}

		b, err = scc.Encode(consig.Con)
		if err != nil {
			logger.Debug(err.Error())
			return
		}
		h, err = scc.Sha256(b)
		if err != nil {
			logger.Debug(err.Error())
			return
		}
		chs := base58.Encode(h, base58.IPFSAlphabet)

		cfn := path.Join(dn, pkhs, fmt.Sprintf("%s.con", chs))
		err = scc.EncodeFile(consig.Con, cfn)
		if err != nil {
			logger.Debug(err.Error())
			return
		}

		sfn := path.Join(dn, pkhs, fmt.Sprintf("%s.con.sig", chs))
		err = scc.EncodeFile(consig.Sig, sfn)
		if err != nil {
			logger.Debug(err.Error())
			return
		}

		sig, err := scc.Sign(b, &sec)
		if err != nil {
			logger.Debug(err.Error())
			return
		}
		b, err = scc.Encode(*sig)
		if err != nil {
			logger.Debug(err.Error())
			return
		}
		w.Write(b)
	})

	listener, err := net.Listen("tcp", a)
	if err != nil {
		os.Exit(5)
	}

	err = fcgi.Serve(listener, handler)
	if err != nil {
		logger.Alert(err.Error())
		os.Exit(6)
	}
}

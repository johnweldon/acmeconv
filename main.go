package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "acmeconv"
	app.Usage = "Convert ACME cache.json to certificate files"
	app.Action = Main
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "cache, c",
			Value: "cache.json",
			Usage: "name of ACME cache.json file",
		},
		cli.StringSliceFlag{
			Name:  "domain, d",
			Value: &cli.StringSlice{"example.com"},
			Usage: "name of domain to extract certificates for",
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}

func Main(c *cli.Context) error {
	cache := c.String("cache")
	account, err := accountFromCache(cache)
	if err != nil {
		return err
	}
	for _, tld := range c.StringSlice("domain") {
		if err := exportAcmeTLD(tld, account); err != nil {
			return err
		}
	}
	return nil
}

func accountFromCache(cachefile string) (*Account, error) {
	account := &Account{}
	b, err := ioutil.ReadFile("cache.json")
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, account); err != nil {
		return nil, err
	}
	return account, nil
}

func exportAcmeTLD(tld string, account *Account) error {
	for _, dc := range account.DomainsCertificate.Certs {
		if dc.Certificate != nil && dc.Certificate.Domain == tld {
			if err := exportCertificate(tld, dc.Certificate); err != nil {
				return err
			}
		}
	}
	return nil
}

func exportCertificate(tld string, cert *Certificate) error {
	pth := path.Join("live", tld)
	if err := os.MkdirAll(pth, os.ModePerm); err != nil {
		return err
	}
	if err := writePemFile(path.Join(pth, "privkey.pem"), [][]byte{cert.PrivateKey}); err != nil {
		return err
	}
	if err := writePemFile(path.Join(pth, "fullchain.pem"), [][]byte{cert.Certificate}); err != nil {
		return err
	}
	if err := writePemFile(path.Join(pth, "cert.pem"), [][]byte{cert.Certificate}); err != nil {
		return err
	}
	return nil
}

func writePemFile(filename string, blocks [][]byte) error {
	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()
	return writePem(out, blocks)
}

func writePem(w io.Writer, blocks [][]byte) error {
	var b *pem.Block
	for _, block := range blocks {
		rest := block
		for {
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if err := pem.Encode(w, b); err != nil {
				return err
			}
		}
	}
	return nil
}

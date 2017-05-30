package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/ejcx/dssss/api"
	"github.com/ejcx/dssss/dc"
	"github.com/ejcx/dssss/fs"
)

var (
	usage = `dssss usage:

$ ./dssss generate
  Generate a new master key.
`
)

const (
	DistinguishedRoles = "RootDSSSS"
	UnsealEnv          = "UNSEAL_KEY"
)

var (
	sess      *session.Session
	UnsealKey []byte
)

func init() {
	unseal := os.Getenv(UnsealEnv)
	u, err := hex.DecodeString(unseal)
	if err != nil {
		log.Fatalf("%s set and is was not hex decode-able: %s", UnsealEnv, err)
	}
	UnsealKey = u
}

func printUsageAndExit() {
	log.Fatalf(usage)
}

func main() {
	flag.Parse()
	if len(flag.Args()) < 1 {
		printUsageAndExit()
	}
	switch flag.Args()[0] {
	case "generate":
		key, err := dc.NewKey()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("MasterKey: %s\n", key)
	case "init":
		_, key, err := fs.NewFS().Initialize()
		if err != nil {
			// We successfully fetched the config file.
			log.Fatalf("Could not initialize. %s", err)
		}
		fmt.Printf("SealKey: %s\n", key)
	case "run":
		if len(UnsealKey) == 0 {
			log.Fatalf("UNSEAL_KEY is unset.")
		}
		c, err := fs.NewFS().LoadConfigFile()
		if err != nil {
			log.Fatalf("Could not initialize. %s", err)
		}
		// We successfully fetched the config file. Ensure that the
		// master key can be decrypted and then start the server!
		var unsealKey [32]byte
		copy(unsealKey[:], UnsealKey)
		masterKey, err := dc.Open(&unsealKey, c.MasterKeyCiphertext)
		if err != nil {
			log.Fatalf("Wrong master key. %s", err)
		}
		var masterKeyLen [32]byte
		copy(masterKeyLen[:], masterKey)
		server := api.NewServer(fs.NewFS(), masterKeyLen)
		server.RunV1()
	case "usage":
	default:
		printUsageAndExit()
	}
}

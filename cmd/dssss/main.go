package main

import (
	"flag"
	"log"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/ejcx/dssss/api"
	"github.com/ejcx/dssss/dc"
	"github.com/ejcx/dssss/fs"
)

var (
	usage = `dssss usage:

$ ./dssss <roles ...>
  This will run dsssss. There are a couple important things to note.
   - If dssss is not initialized, dssss will initialize itself.
   - If dssss is already initialized it will attempt to load it's
   configuration file from the AWS parameter store, and boot up.

$ ./dssss usage
  Print this beautiful usage message.
`
)

var (
	sess               *session.Session
	UnsealKey          []byte
	OtherDistinguished []string
)

func printUsageAndExit() {
	log.Fatalf(usage)
}

func init() {
	flag.Parse()
}
func main() {
	var (
		key *dc.Key
		c   *fs.ConfigFile
		err error
	)
	if len(flag.Args()) > 0 {
		switch flag.Args()[0] {
		case "usage":
		default:
			printUsageAndExit()
		}
	}

	c, key, err = fs.NewFS(nil).Initialize()
	if err != nil {
		// We successfully fetched the config file.
		log.Fatalf("Could not initialize. %s", err)
	}
	// We successfully fetched the config file. Ensure that the
	// master key can be decrypted and then start the server!
	server := api.NewServer(fs.NewFS(c), key.Bytes)
	server.RunV1()
}

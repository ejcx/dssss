package fs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/ejcx/dssss/dc"
)

var (
	DSConfig = "config.json"
)

type ConfigFile struct {
	MasterKeyCiphertext []byte
}

// FS provides the methods necessary in order to manage the files
// and data that dssss needs. Under the hood, FS just holds an
// s3 session.
type FS struct {
	Downloader *s3manager.Downloader
	Uploader   *s3manager.Uploader
	Sess       *session.Session
	Bucket     string
}

func (f *FS) ReadFile(fname string) ([]byte, error) {
	var b []byte
	buf := aws.NewWriteAtBuffer(b)
	n, err := f.Downloader.Download(buf, &s3.GetObjectInput{
		Bucket: aws.String(f.Bucket),
		Key:    aws.String(fname),
	})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		log.Printf("File is empty: %s\n", fname)
	}
	return buf.Bytes(), err
}

func (f *FS) getConfigFile() ([]byte, error) {
	s, err := f.ReadFile(DSConfig)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (f *FS) LoadConfigFile() (*ConfigFile, error) {
	var (
		c ConfigFile
	)
	s, err := f.getConfigFile()
	if err != nil {
		return nil, err
	}
	if len(s) == 0 {
		return nil, errors.New("Empty response")
	}
	err = json.Unmarshal(s, &c)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Invalid json: %s", err))
	}
	return &c, nil
}

func initializeConfig() (*ConfigFile, *dc.Key, error) {
	masterKey, err := dc.NewKey()
	if err != nil {
		return nil, nil, errors.New(fmt.Sprint("Could not create new master key: %s", err))
	}
	sealKey, err := dc.NewKey()
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("Could not create new seal key: %s", err))
	}

	// Encrypt the masterKey with the sealKey. The seal key
	// is what we expose to the user.
	cipher, err := dc.Seal(&sealKey.Bytes, masterKey.Bytes[:])
	if err != nil {
		return nil, sealKey, err
	}
	return &ConfigFile{
		MasterKeyCiphertext: cipher,
	}, sealKey, nil
}

func (f *FS) WriteSecret(name string, i interface{}) error {
	buf, err := json.MarshalIndent(i, " ", "    ")
	if err != nil {
		return err
	}
	if len(buf) == 2 {
		buf = []byte{}
	}
	_, err = f.Uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(f.Bucket),
		Key:    aws.String("secret/" + name),
		Body:   bytes.NewReader(buf),
	})
	if err != nil {
		return err
	}
	return nil
}

func (f *FS) Initialize() (*ConfigFile, *dc.Key, error) {
	var (
		c *ConfigFile
	)
	_, err := f.getConfigFile()
	// We found a config file. This is a problem.
	// Don't initialize on top of a config.
	if err == nil {
		return nil, nil, errors.New("Config file already exists")
	}

	// Since we don't already have a config file. Make one.
	c, key, err := initializeConfig()
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("Could not create config: %s", err))
	}
	buf, err := json.Marshal(c)
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("Could not marshal config before upload: %s", err))
	}
	_, err = f.Uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(f.Bucket),
		Key:    aws.String(DSConfig),
		Body:   bytes.NewReader(buf),
	})
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("Could not upload config: %s", err))
	}
	return c, key, err

}

func NewFS() *FS {
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-west-1"),
	}))
	downloader := s3manager.NewDownloader(sess)
	uploader := s3manager.NewUploader(sess)
	return &FS{
		Downloader: downloader,
		Uploader:   uploader,
		Bucket:     "dssss",
	}
}

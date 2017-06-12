package fs

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/ejcx/dssss/dc"
)

var (
	DSConfig = "config.json"
	sess     *session.Session
)

type ConfigFile struct {
	MasterKeyCiphertext []byte
	KMSArn              string
	Active              bool
}

// FS provides the methods necessary in order to manage the files
// and data that dssss needs. Under the hood, FS just holds an
// s3 session.
type FS struct {
	SSM       *ssm.SSM
	Namespace string
	KMSArn    string
}

func init() {
	sess = session.Must(session.NewSession(&aws.Config{}))
}

func (f *FS) ReadFile(fname string) (string, error) {
	g := &ssm.GetParametersInput{
		Names:          []*string{aws.String(".dssss." + fname)},
		WithDecryption: aws.Bool(true),
	}
	o, err := f.SSM.GetParameters(g)
	if err != nil {
		return "", err
	}
	if len(o.InvalidParameters) != 0 {
		return "", errors.New("Invalid parameters found.")
	}
	if len(o.Parameters) != 1 {
		return "", errors.New("Too many parameters found..")
	}
	return *o.Parameters[0].Value, nil
}

func (f *FS) getConfigFile() ([]byte, error) {
	s, err := f.ReadFile(DSConfig)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
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
	var (
		masterKey [32]byte
	)
	keyArn, err := createKMSAndDataKey()
	if err != nil {
		return nil, nil, err
	}
	svc := kms.New(sess)
	genKeyInput := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyArn),
		KeySpec: aws.String(kms.DataKeySpecAes256),
	}
	out, err := svc.GenerateDataKey(genKeyInput)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not generate new kms data key: %s", err)
	}
	copy(masterKey[:], out.Plaintext)

	return &ConfigFile{
		MasterKeyCiphertext: out.CiphertextBlob,
		Active:              true,
		KMSArn:              keyArn,
	}, &dc.Key{Bytes: masterKey}, nil
}

func (f *FS) ListSecret(filter string) ([]string, error) {
	var (
		secrets []string
	)
	filters := []*string{aws.String(".dssss.secret." + filter)}
	d := &ssm.DescribeParametersInput{
		MaxResults: aws.Int64(50),
		Filters: []*ssm.ParametersFilter{
			&ssm.ParametersFilter{Key: aws.String("Name"), Values: filters},
		},
	}
	for {
		desc, err := f.SSM.DescribeParameters(d)
		if err != nil {
			return nil, err
		}
		for _, p := range desc.Parameters {
			n := strings.Replace(*p.Name, ".dssss.secret.", "", 1)
			secrets = append(secrets, n)
		}
		if desc.NextToken != nil {
			d.NextToken = desc.NextToken
			continue
		} else {
			break
		}
	}
	return secrets, nil
}

func (f *FS) DeleteSecret(name string) error {
	d := &ssm.DeleteParameterInput{
		Name: aws.String(".dssss.secret." + name),
	}
	_, err := f.SSM.DeleteParameter(d)
	if err != nil {
		return err
	}
	return nil
}

func (f *FS) WriteSecret(name string, i interface{}) error {
	buf, err := json.MarshalIndent(i, " ", "    ")
	if err != nil {
		return err
	}
	if len(buf) == 2 {
		buf = []byte{}
	}
	s := &ssm.PutParameterInput{
		Type:  aws.String("SecureString"),
		Value: aws.String(string(buf)),
		Name:  aws.String(".dssss." + name),
		KeyId: &f.KMSArn,
	}
	_, err = f.SSM.PutParameter(s)
	if err != nil {
		return err
	}
	return nil
}

func createKMSAndDataKey() (string, error) {
	svc := kms.New(sess)
	k := &kms.CreateKeyInput{
		Description: aws.String("DSSSS Key"),
		KeyUsage:    aws.String("ENCRYPT_DECRYPT"),
	}
	result, err := svc.CreateKey(k)
	if err != nil {
		return "", fmt.Errorf("Could not create key: %s", err)
	}
	if result == nil {
		return "", errors.New("No key returned. Failure creating KMS key")
	}
	return *result.KeyMetadata.Arn, nil
}

func decryptMasterKey(ciphertext []byte) (*dc.Key, error) {
	var (
		masterKey [32]byte
	)
	svc := kms.New(sess)
	d := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	}
	plain, err := svc.Decrypt(d)
	if err != nil {
		return nil, err
	}
	copy(masterKey[:], plain.Plaintext)
	return &dc.Key{
		Bytes: masterKey,
	}, nil
}

func (f *FS) Initialize() (*ConfigFile, *dc.Key, error) {
	var (
		c   *ConfigFile
		key *dc.Key
	)
	d, err := f.getConfigFile()
	// We found an existing config file. Use it!
	if err == nil {
		err = json.Unmarshal(d, &c)
		if err != nil {
			return nil, nil, fmt.Errorf("Could not attempt to fetch current config: %s", err)
		}
		// We already have an initialized dssss!
		if c != nil && c.Active {
			// We might as well decrypt the master seal key and
			// head back home to kick of starting the server.
			key, err = decryptMasterKey(c.MasterKeyCiphertext)
			if err != nil {
				return nil, nil, fmt.Errorf("Found existing config but was not able to use it: %s", err)
			}
			return c, key, nil
		}
	}

	// Since we don't already have a config file. Make one.
	c, key, err = initializeConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create config objects: %s", err)
	}
	buf, err := json.Marshal(c)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not marshal config before upload: %s", err)
	}
	_, err = f.SSM.PutParameter(&ssm.PutParameterInput{
		Type:  aws.String("SecureString"),
		Value: aws.String(string(buf)),
		Name:  aws.String(".dssss." + DSConfig),
	})
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("Could not upload config: %s", err))
	}
	return c, key, err
}

func NewFS(c *ConfigFile) *FS {
	svc := ssm.New(sess)

	kmsArn := ""
	if c != nil {
		kmsArn = c.KMSArn
	}
	return &FS{
		Namespace: ".dssss.",
		SSM:       svc,
		KMSArn:    kmsArn,
	}
}

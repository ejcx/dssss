package auth

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/fullsailor/pkcs7"
)

type AWSInstanceIdentity struct {
	DevpayProductCodes interface{} `json:"devpayProductCodes"`
	PrivateIP          string      `json:"privateIp"`
	AvailabilityZone   string      `json:"availabilityZone"`
	Version            string      `json:"version"`
	InstanceID         string      `json:"instanceId"`
	BillingProducts    interface{} `json:"billingProducts"`
	InstanceType       string      `json:"instanceType"`
	ImageID            string      `json:"imageId"`
	PendingTime        time.Time   `json:"pendingTime"`
	AccountID          string      `json:"accountId"`
	Architecture       string      `json:"architecture"`
	KernelID           interface{} `json:"kernelId"`
	RamdiskID          interface{} `json:"ramdiskId"`
	Region             string      `json:"region"`
}

const (
	AWSCertificate = `-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----
`
)

type Auth struct {
	Role string
}

//
// Look at github.com/hashicorp/vault/builtin/credential/aws/path_login.go
// This contains an example for how to do AWS authentication with an
// AWS Identity Document.
// Once you have the AWS Identity Document, you need to query the AWS
// instance, fetch the AMI-ID, and finally get the Role ARN and Role Name.
// Don't forget to validate the AWS Identity Document.

func getawscert() ([]*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(AWSCertificate))
	if len(rest) != 0 {
		return nil, fmt.Errorf("Failed to decode cert. Invalid.")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, fmt.Errorf("Invalid certificate")
	}
	return []*x509.Certificate{cert}, nil

}

func ParsePKCS7(pkcs7raw string) (*AWSInstanceIdentity, error) {
	var (
		a AWSInstanceIdentity
	)
	pkcs7Armored := fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", pkcs7raw)
	pkcs7ber, pkcs7rest := pem.Decode([]byte(pkcs7Armored))
	if len(pkcs7rest) != 0 {
		return nil, errors.New("Could not decode armored pkcs7")
	}

	pkcs7data, err := pkcs7.Parse(pkcs7ber.Bytes)
	if err != nil {
		return nil, err
	}

	certs, err := getawscert()
	if err != nil {
		return nil, fmt.Errorf("Could not get aws cert: %s", err)
	}
	pkcs7data.Certificates = certs
	if pkcs7data.Verify() != nil {
		return nil, fmt.Errorf("Could not verify pkcs7\n")
	}
	err = json.Unmarshal(pkcs7data.Content, &a)
	return &a, err
}

func LoadInstance(identity *AWSInstanceIdentity) (*ec2.Instance, error) {
	// Use the identity to get information about the instance.
	sess := session.Must(session.NewSession(&aws.Config{
		// Use the region from the identity document
		// to make looking up the instance id easy.
		Region: aws.String(identity.Region),
	}))
	svc := ec2.New(sess)
	status, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(identity.InstanceID),
		},
	})
	if err != nil {
		return nil, err
	}
	if len(status.Reservations) == 0 {
		return nil, errors.New("No found reservations with instance id")
	}

	if len(status.Reservations[0].Instances) == 0 {
		return nil, errors.New("No instances found with reservation")
	}
	awsInstanceId := *status.Reservations[0].Instances[0].InstanceId
	if awsInstanceId != identity.InstanceID {
		return nil, fmt.Errorf("Unexpected instanceId returned by aws %s", awsInstanceId)
	}

	// Make sure this instance is still running too. None of those
	// week old pkcs7's should be allowed here.
	if status.Reservations[0].Instances[0].State == nil {
		return nil, fmt.Errorf("Invalid state returned by aws.")
	}
	if *status.Reservations[0].Instances[0].State.Name != "running" {
		return nil, fmt.Errorf("State is not running. No longer eligible instance.")
	}

	// Once we have the instance profile, we need to fetch the instance
	// profile from the iam api.
	instance := status.Reservations[0].Instances[0]
	return instance, nil
}

func LoadInstanceProfile(region string, instanceProfile *ec2.IamInstanceProfile) (*iam.InstanceProfile, error) {
	instanceProfileTuple := strings.SplitAfter(*instanceProfile.Arn, ":instance-profile/")
	name := instanceProfileTuple[len(instanceProfileTuple)-1]
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	svcIam := iam.New(sess)
	instanceProfileOutput, err := svcIam.GetInstanceProfile(&iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(name),
	})
	if err != nil {
		return nil, err
	}

	// Finally we have the instance profile with roles.
	return instanceProfileOutput.InstanceProfile, nil
}

// AuthUser follows the auth process necessary to validate
// a user's pkcs7 metadata:
//   1. Take the PKCS7 and validate the signature and parse identity doc.
//   2. Use the identity document to determine the instance profile name.
//   3. Use the instance profile name to look up the entire instance profile.
//   4. The instance profile contains the roles associated with the instance
//
// Finally, we can return an "Auth" object which describes which
// role you have authenticated as. Thanks AWS. I dig it.
func AuthUser(pkcs7raw string) (*Auth, error) {
	identity, err := ParsePKCS7(pkcs7raw)
	if err != nil {
		return nil, err
	}

	instance, err := LoadInstance(identity)
	if err != nil {
		return nil, err
	}
	ec2instanceProfile := instance.IamInstanceProfile

	instanceProfile, err := LoadInstanceProfile(identity.Region, ec2instanceProfile)
	if err != nil {
		return nil, err
	}

	if len(instanceProfile.Roles) == 0 {
		return nil, errors.New("Authenticated, but does no associated roles with instance")
	}

	return &Auth{Role: *instanceProfile.Roles[0].RoleName}, nil
}

func (a *Auth) IsAllowed(roleList []string) error {
	for _, role := range roleList {
		if role == a.Role {
			return nil
		}
	}
	return fmt.Errorf("Did not find role %s in allowed role list", a.Role)
}

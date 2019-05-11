package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/m-mizutani/deepalert"
	"github.com/pkg/errors"
)

type Arguments struct {
	Attr      deepalert.Attribute
	SecretArn string
}

func getSecretValues(secretArn string, values interface{}) error {
	// sample: arn:aws:secretsmanager:ap-northeast-1:1234567890:secret:mytest
	arn := strings.Split(secretArn, ":")
	if len(arn) != 7 {
		return errors.New(fmt.Sprintf("Invalid SecretsManager ARN format: %s", secretArn))
	}
	region := arn[3]

	ssn := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	mgr := secretsmanager.New(ssn)

	result, err := mgr.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretArn),
	})

	if err != nil {
		return errors.Wrap(err, "Fail to retrieve secret values")
	}

	err = json.Unmarshal([]byte(*result.SecretString), values)
	if err != nil {
		return errors.Wrap(err, "Fail to parse secret values as JSON")
	}

	return nil
}

type falconSecrets struct {
	FalconUser  string `json:"falcon_user"`
	FalconToken string `json:"falcon_token"`
}

func Handler(args Arguments) (deepalert.ReportContentEntity, error) {
	if args.Attr.Type != deepalert.TypeIPAddr {
		return nil, nil
	}

	var secrets falconSecrets
	if err := getSecretValues(args.SecretArn, &secrets); err != nil {
		return nil, errors.Wrapf(err, "Fail to get values from SecretsManager: %s", args.SecretArn)
	}

	client := newFalconClient(secrets.FalconUser, secrets.FalconToken)
	searchResp, err := client.newDeviceSearchQuery().
		addFilter("external_ip", args.Attr.Value).
		run()
	if err != nil {
		return nil, errors.Wrap(err, "Fail to search External IP address")
	}

	if len(searchResp.Resources) != 1 {
		// Resource not found or too main resources under same IP address.
		return nil, nil
	}

	device, err := client.newDeviceQuery(searchResp.Resources).run()
	if err != nil {
		return nil, errors.Wrapf(err, "Fail to get device infomation: %v", searchResp.Resources)
	}

	if len(device.Resources) != 1 {
		return nil, errors.Wrapf(err, "Unexpected response (number of resources must be 1): %v", device)
	}

	resource := device.Resources[0]
	host := deepalert.ReportHost{
		IPAddr: []string{
			resource.ExternalIP,
			resource.LocalIP,
		},
		OS: []string{
			resource.PlatformName,
			resource.OsVersion,
		},
		MACAddr: []string{
			strings.ReplaceAll(resource.MacAddress, "-", ":"),
		},
		HostName: []string{
			resource.Hostname,
		},
	}

	return &host, nil
}

func lambdaHandler(ctx context.Context, attr deepalert.Attribute) (deepalert.ReportContentEntity, error) {
	args := Arguments{
		Attr:      attr,
		SecretArn: os.Getenv("SecretArn"),
	}
	return Handler(args)
}

func main() {
	deepalert.StartInspector(lambdaHandler, "crowdstrike-falcon", os.Getenv("SUBMIT_TOPIC"))
}

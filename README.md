# DeepAlert Inspector: CrowdStrike Flacon

DeepAlert inspector for CrowdStrike Falcon.

## Prerequisite

- awscli >= 1.16.130
- go >= 1.12.2

## Deploy

Prepare `config.json` like the following.

```json
{
  "StackName": "deepalert-crowdstrike-falcon",
  "Region": "ap-northeast-1",
  "CodeS3Bucket": "your-bucket-name",
  "CodeS3Prefix": "functions",

  "SecretArn": "arn:aws:secretsmanager:ap-northeast-1:1234567890:secret:your-secrets-XXXXXX",
  "DeepAlertStackName": "deepalert-stack"
}
```

`SecretArn` is ARN of SecretsManager's secret. The secret must have following items.

- `falcon_user`: Username of CrowdStrike Falcon API.
- `falcon_token`: Access Token of CrowdStrike Falcon API.

## Test

You can test by `go test` command with following environment variables.

- `DA_TEST_SECRET`: Required. ARN of SecretsManager secret.
- `DA_TEST_IPADDR`: Optional. global IP address of a client that is installed CrowdStrike Falcon sensor. External IP address of NAT is also good.

## Author

- Masayoshi MIZUTANI < mizutani@sfc.wide.ad.jp >
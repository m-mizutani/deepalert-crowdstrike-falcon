module github.com/m-mizutani/deepalert-crowdstrike-falcon

go 1.12

require (
	github.com/aws/aws-lambda-go v1.13.2 // indirect
	github.com/aws/aws-sdk-go v1.24.0
	github.com/guregu/dynamo v1.4.1 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/m-mizutani/deepalert v0.0.0-20190821013142-d7431b074ed2
	github.com/pkg/errors v0.8.1
	github.com/stretchr/testify v1.4.0
	golang.org/x/net v0.0.0-20190916140828-c8589233b77d // indirect
	golang.org/x/sys v0.0.0-20190916202348-b4ddaad3f8a3 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
)

replace gopkg.in/urfave/cli.v1 => github.com/urfave/cli v1.21.0

[![Go Report Card](https://goreportcard.com/badge/github.com/tenorwill/awsmfa)](https://goreportcard.com/report/github.com/tenorwill/awsmfa)
[![Go](https://github.com/tenorwill/awsmfa/actions/workflows/go.yml/badge.svg)](https://github.com/tenorwill/awsmfa/actions/workflows/go.yml)
<hr>
<p align="center">
  <img src="https://github.com/tenorwill/awsmfa/blob/main/reference/go.png" width="150" height="150">
</p>
<h1 align="center">awsmfa</h1>
<h4 align="center">A Cross-platform MFA Token Generator written in Go</h4>
<hr>

## Summary
This is a simple program that generates a session token for an AWS IAM user or assumes a role based on profiles. It differs from other similar programs in that it asks for input as you go. Once the token is generated, it's copied to the credentials file using the ini Go package.

## Compatibility
Works on Windows! Thanks to `https://github.com/fatih/color`, coloring is easy to use and works perfectly in Windows, MacOS and Linux
### Assumptions
This program assumes you have already configured your AWS config and credentials files (usually `~/.aws/config` & `~/.aws/credentials`)

```
~/.aws/credentials:
[default]
aws_access_key_id = AKXXXXXXXXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXX

~/.aws/config:
[profile myprofile]
mfa_serial = arn:aws:iam::AccountNumber:mfa/username

[profile myotherprofile]
role_arn = arn:aws:iam::1234567890:role/myrole
source_profile = default
mfa_serial = arn:aws:iam::AnotherAccountNumber:mfa/username
```

<details>
    <summary><em>TL;DR - Quick List</em></summary>

#### Steps
>- `go build -v && ./awsmfa` or `go build -v && ./awsmfa -u`
>- follow prompts

</details>
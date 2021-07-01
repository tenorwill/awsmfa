// =======================================================
// Title: awsmfa
// Description: Get Session Token or Assume Role with MFA
// =======================================================

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"gopkg.in/ini.v1"

	homedir "github.com/mitchellh/go-homedir"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Use Fatih Color Package for nice output
var (
	cb   = color.New(color.FgCyan).Add(color.Bold)
	cy   = color.New(color.FgCyan)
	gb   = color.New(color.FgGreen).Add(color.Bold)
	ge   = color.New(color.FgGreen)
	rb   = color.New(color.FgRed).Add(color.Bold)
	re   = color.New(color.FgRed)
	yb   = color.New(color.FgYellow).Add(color.Bold)
	cyan = color.New(color.FgCyan).Add(color.Bold).SprintFunc()
)

// Credentials & Config File Paths
var (
	awsCredsPath  string
	awsConfigPath string
)

// Header variables
var t = time.Now()
var title = "awsmfa"
var description = "Get Session Token or Assume Role with MFA"
var date = t.Format("2006-01-02 15:04:05")

// Header
func header(title, curDate, description string) string {
	hlines := strings.Repeat("-", 62)
	header := hlines + "\n" +
		"Script: " + title + "\n" +
		"Description: " + description + "\n" +
		"Date: " + curDate + "\n" +
		hlines + "\n"
	return header
}

// Message to indicate expected config and credentials file formats
func h2() {
	h2lines := strings.Repeat("-", 62)
	h2text := `
This script expects the AWS config and credentials
file to be configured in this example format:`
	rb.Println(h2lines, h2text, "\n")
	yb.Println("~/.aws/credentials:")
	fmt.Println(`[default]
aws_access_key_id = AKXXXXXXXXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXX)`)
	fmt.Print("\n")
	yb.Println("~/.aws/config:")
	fmt.Println(`[profile myprofile]
mfa_serial = arn:aws:iam::AccountNumber:mfa/username

[profile myotherprofile]
role_arn = arn:aws:iam::1234567890:role/myrole
source_profile = default
mfa_serial = arn:aws:iam::AnotherAccountNumber:mfa/username`)
	rb.Println(h2lines, "\n")
	return
}

// Flags: user for get_session_token or default role assumption
var (
	userFlag = flag.Bool("user", false, "AWS User")
)

// This extends flags for short forms, custom usage
func usage() {}

func init() {

	flag.BoolVar(userFlag, "u", false, "User flag")

	flag.Usage = func() {
		cb.Println(header(title, date, description))
		cb.Println(("Usage: ") + os.Args[0])
		cb.Println("Example: ./awsmfa -u \n")
		flagOptions := "-u | --user AWS User (optional - default: none)\n"
		cb.Println(flagOptions)

	}
}

// Menu options with default values
func menuInput(userFlag bool) (string, string, string, int32, string) {
	// Credentials file ini sections
	cb.Print("Enter AWS Credentials: ")
	fmt.Print("(\"default\"): ")
	var awsCreds string
	fmt.Scanln(&awsCreds)
	if len(awsCreds) == 0 {
		awsCreds = "default"
		gb.Println(awsCreds)
	} else {
		gb.Println(awsCreds)
	}

	// Assume a role (default) or get session token with -u | --user flag
	var awsProfile string
	if userFlag == false {
		cb.Print("Enter profile name for role assumption: ")
		fmt.Print("(\"default\"): ")
		fmt.Scanln(&awsProfile)
		if len(awsProfile) == 0 {
			awsProfile = "default"
			gb.Println(awsProfile)
		} else {
			gb.Println(awsProfile)
		}
	} else {
		cb.Print("Enter profile name to get session token: ")
		fmt.Print("(\"default\"): ")
		fmt.Scanln(&awsProfile)
		if len(awsProfile) == 0 {
			awsProfile = "default"
			gb.Println(awsProfile)
		} else {
			gb.Println(awsProfile)
		}
	}

	// Region with us-east-1 as a default value
	cb.Print("Enter AWS Region: ")
	fmt.Print("(\"us-east-1\"): ")
	var awsRegion string
	fmt.Scanln(&awsRegion)
	if len(awsRegion) == 0 {
		awsRegion = "us-east-1"
		gb.Println(awsRegion)
	} else {
		gb.Println(awsRegion)
	}

	// Token duration in seconds (default is 12 hours or 28800 seconds)
	cb.Print("Enter Duration (s): ")
	fmt.Print("(\"28800 - 8 hours\"): ")
	var strDuration string
	var d int
	var duration int32
	// Validate the input is numeric (int)
	for {
		_, err := fmt.Scanln(&strDuration)
		if len(strDuration) == 0 {
			strDuration = "28800"
		}
		d, err = strconv.Atoi(strDuration)
		duration = int32(d)
		if err != nil {
			rb.Print("Please enter a valid duration, minimum 900 (s): ")
		} else {
			gb.Println(duration)
			break
		}
	}

	// MFA token which is used to assume the role or get session token
	cb.Print("Enter MFA Token: ")
	fmt.Print("(\"123456\"): ")
	var tokenCode string
	// No default value, MFA Token must be entered
	for {
		_, err := fmt.Scanln(&tokenCode)
		if err != nil {
			rb.Print("Please enter a valid token code: ")
		} else {
			gb.Println(tokenCode, "\n")
			break
		}
	}

	return awsCreds, awsRegion, awsProfile, duration, tokenCode
}

// Get the home directory location
func homeDir() string {
	homeDir, err := homedir.Dir()
	if err != nil {
		fmt.Printf("Unable to get home directory location \nError: %v", err.Error())
		os.Exit(1)
	}
	return homeDir
}

// Useful check for error and exit function when the program should immediately terminate
func checkErrorAndExit(err error, msg string) {
	if err != nil {
		rb.Printf("%s \nError: %s \n", msg, err.Error())
		os.Exit(2)
	}
}

// ResultCred Struct of Temporary Credentials
type ResultCred struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Expiration   string
}

// Load AWS Config and Credentials Files using ini package
func loadAwsConfig() (*ini.File, *ini.File) {
	cred, err := ini.Load(awsCredsPath)
	checkErrorAndExit(err, "Failed to load credentials file")

	cfg, err := ini.Load(awsConfigPath)
	checkErrorAndExit(err, "Failed to load config file")

	return cred, cfg
}

// Get Session Token when -u | --user flag is entered
func getSessionToken(awsCreds string, awsRegion string, awsProfile string, duration int32, tokenCode string) {
	// Load AWS Config and Credentials Files
	cred, cfg := loadAwsConfig()

	mfaProfile := awsProfile + "_mfa"
	serialMfa := cfg.Section("profile " + awsProfile).Key("mfa_serial").String()
	c, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(awsCreds),
		config.WithDefaultRegion(awsRegion),
	)

	checkErrorAndExit(err, "Cannot load aws credentials file")

	// Use GetSessionToken API to get session token
	stsClient := sts.NewFromConfig(c)
	token, err := stsClient.GetSessionToken(context.TODO(), &sts.GetSessionTokenInput{
		DurationSeconds: &duration,
		SerialNumber:    &serialMfa,
		TokenCode:       &tokenCode,
	})

	checkErrorAndExit(err, "Problem getting session token")

	saveSessionTokenToCredentials(cred, mfaProfile, *token)
}

// Assume Role (default behaviour)
func assumeRole(awsCreds string, awsRegion string, awsProfile string, duration int32, tokenCode string) {
	// Load AWS Config and Credentials Files
	cred, cfg := loadAwsConfig()

	mfaProfile := awsProfile + "_mfa"
	serialMfa := cfg.Section("profile " + awsProfile).Key("mfa_serial").String()
	roleArn := cfg.Section("profile " + awsProfile).Key("role_arn").String()
	roleSessionName := awsProfile + "_session_name"

	c, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(awsCreds),
	)

	checkErrorAndExit(err, "Cannot load aws credentials file")

	// STS Assume Role Function to get temporary credentials
	stsClient := sts.NewFromConfig(c)
	token, err := stsClient.AssumeRole(context.TODO(), &sts.AssumeRoleInput{
		DurationSeconds: &duration,
		SerialNumber:    &serialMfa,
		RoleArn:         &roleArn,
		RoleSessionName: &roleSessionName,
		TokenCode:       &tokenCode,
	})

	checkErrorAndExit(err, "Problem getting session token")

	saveAssumedRoleCredentials(cred, mfaProfile, *token)

}

// Save Session Token Info to Credentials File with profile_mfa name
func saveSessionTokenToCredentials(cred *ini.File, mfaProfile string, token sts.GetSessionTokenOutput) {
	// Use ResultCred Struct to pass values into ini file and credOutput
	r := ResultCred{
		AccessKey:    *token.Credentials.AccessKeyId,
		SecretKey:    *token.Credentials.SecretAccessKey,
		SessionToken: *token.Credentials.SessionToken,
		Expiration:   token.Credentials.Expiration.Format(time.RFC3339),
	}

	// Save to ini file, error out if thtere are issues
	cred.Section(mfaProfile).Key("aws_access_key_id").SetValue(r.AccessKey)
	cred.Section(mfaProfile).Key("aws_secret_access_key").SetValue(r.SecretKey)
	cred.Section(mfaProfile).Key("aws_session_token").SetValue(r.SessionToken)
	cred.Section(mfaProfile).Key("expiration").SetValue(r.Expiration)

	if err := cred.SaveTo(awsCredsPath); err != nil {
		rb.Printf("Failed to save to credentials file \nError: %v", err.Error())
	}

	credOutput(&r, mfaProfile)
}

// Save Assumed Role Token Info to Credentials File with profile_mfa name
func saveAssumedRoleCredentials(cred *ini.File, mfaProfile string, token sts.AssumeRoleOutput) {
	// Use ResultCred Struct to pass values into ini file and credOutput
	r := ResultCred{
		AccessKey:    *token.Credentials.AccessKeyId,
		SecretKey:    *token.Credentials.SecretAccessKey,
		SessionToken: *token.Credentials.SessionToken,
		Expiration:   token.Credentials.Expiration.Format(time.RFC3339),
	}

	// Save to ini file, error out if thtere are issues
	cred.Section(mfaProfile).Key("aws_access_key_id").SetValue(r.AccessKey)
	cred.Section(mfaProfile).Key("aws_secret_access_key").SetValue(r.SecretKey)
	cred.Section(mfaProfile).Key("aws_session_token").SetValue(r.SessionToken)
	cred.Section(mfaProfile).Key("expiration").SetValue(r.Expiration)

	if err := cred.SaveTo(awsCredsPath); err != nil {
		rb.Printf("Failed to save to credentials file \nError: %v", err.Error())
	}
	credOutput(&r, mfaProfile)
}

// Final output including a switch for bash vs windows
func credOutput(r *ResultCred, mfaProfile string) {

	// Short footer with final output
	fLines := strings.Repeat("-", 76) + "\n"
	msg := "Temporary Creds for Profile " + mfaProfile + " are saved to AWS Credentials File" + "\n"
	exp := "Expiration: " + r.Expiration + "\n"
	msg2 := `Environment Variables: If you want to use ENV variables instead, export 
as per below (copy & paste in shell)
`
	cb.Print(fLines, msg, exp, msg2, fLines, "\n")

	cliShell := "bash"
	if runtime.GOOS == "windows" {
		cliShell = "cmdpwshell"
	}

	switch cliShell {
	case "bash":
		envBashVars := `export AWS_PROFILE=%s
unset AWS_SESSION_TOKEN
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN=%s
AWS_ACCESS_KEY_ID=%s
AWS_SECRET_ACCESS_KEY=%s
export AWS_SESSION_TOKEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY`

		interpolatedEnvVars := fmt.Sprintf(envBashVars, mfaProfile, r.SessionToken, r.AccessKey, r.SecretKey)
		ge.Println(interpolatedEnvVars, "\n")

	case "cmdpwshell":
		envWinVars := `# Windows Command Prompt:
setx AWS_PROFILE %s
setx AWS_SESSION_TOKEN %s
setx AWS_ACCESS_KEY_ID %s
setx AWS_SECRET_ACCESS_KEY %s

# Windows PowerShell:
$Env:AWS_SESSION_TOKEN="%s"
$Env:AWS_ACCESS_KEY_ID="%s"
$Env:AWS_SECRET_ACCESS_KEY="%s"`

		interpolatedEnvVars := fmt.Sprintf(envWinVars, mfaProfile, r.SessionToken, r.AccessKey, r.SecretKey, r.SessionToken, r.AccessKey, r.SecretKey)
		ge.Println(interpolatedEnvVars, "\n")
	}

	gb.Println("Done!")
}

// Let's Go
func main() {

	// Parse Flags (only one)
	flag.Parse()

	// Print headers
	cb.Println(header(title, date, description))
	h2()

	// Default behaviour without -u | --user flag assumes a role,
	// print message to screen indicating the function
	if *userFlag == true {
		gb.Println("Using the get_session_token user flag")
	} else {
		yb.Println("Not using the user flag - proceeding with role assumption")
	}

	// Run the menu parser, retrieve results
	awsCreds, awsRegion, awsProfile, duration, tokenCode := menuInput(*userFlag)

	// Use homeDir function to get AWS config and credentials file absolute path
	awsCredsPath = homeDir() + "/.aws/credentials"
	awsConfigPath = homeDir() + "/.aws/config"

	// Get a Session Token or Assume a Role
	if *userFlag == true {
		getSessionToken(awsCreds, awsRegion, awsProfile, duration, tokenCode)
	} else {
		assumeRole(awsCreds, awsRegion, awsProfile, duration, tokenCode)
	}

}

// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tester

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/trace"

	kyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// SSOTestCommand implements common.CLICommand interface
type SSOTestCommand struct {
	config *service.Config

	ssoTestCmd *kingpin.CmdClause

	// connectorFileName points at file name with sso connector definition
	connectorFileName string

	// Handlers is a mapping between auth kind and appropriate handling function
	Handlers map[string]func(c auth.ClientI, connBytes []byte) (*AuthRequestInfo, error)
	// GetDiagInfoFields provides auth kind-specific diagnostic info fields.
	GetDiagInfoFields map[string]func(diag *types.SSODiagnosticInfo, debug bool) []DiagnosticInfoField
}

// Initialize allows a caller-defined command to plug itself into CLI
// argument parsing
func (cmd *SSOTestCommand) Initialize(app *kingpin.Application, cfg *service.Config) {
	cmd.config = cfg

	sso := app.GetCommand("sso")
	cmd.ssoTestCmd = sso.Command("test", "Test SSO auth connector")
	cmd.ssoTestCmd.Arg("filename", "Connector resource definition filename, empty for stdin").StringVar(&cmd.connectorFileName)

	cmd.Handlers = map[string]func(c auth.ClientI, connBytes []byte) (*AuthRequestInfo, error){
		types.KindGithubConnector: handleGithubConnector,
	}

	cmd.GetDiagInfoFields = map[string]func(diag *types.SSODiagnosticInfo, debug bool) []DiagnosticInfoField{
		types.KindGithubConnector: getGithubDiagInfoFields,
	}
}

func (cmd *SSOTestCommand) ssoTestCommand(c auth.ClientI) error {
	reader := os.Stdin
	if cmd.connectorFileName != "" {
		f, err := utils.OpenFile(cmd.connectorFileName)
		if err != nil {
			return trace.Wrap(err, "could not open connector spec file %v", cmd.connectorFileName)
		}
		defer f.Close()
		reader = f
	}

	decoder := kyaml.NewYAMLOrJSONDecoder(reader, defaults.LookaheadBufSize)
	for {
		var raw services.UnknownResource
		err := decoder.Decode(&raw)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return trace.Wrap(err, "Unable to load resource. Make sure the file is in correct format.")
		}

		handler, ok := cmd.Handlers[raw.Kind]
		if !ok {
			var kinds []string
			for kind := range cmd.Handlers {
				kinds = append(kinds, kind)
			}
			return trace.BadParameter("Resources of type %q are not supported. Supported kinds: %v", raw.Kind, kinds)
		}

		requestInfo, err := handler(c, raw.Raw)
		if err != nil {
			return trace.Wrap(err)
		}

		// note: loginErr is processed further down.
		loginResponse, loginErr := cmd.runSSOLoginFlow(context.TODO(), raw.Kind, c, requestInfo.Config)

		if requestInfo.RequestCreateErr != nil {
			return trace.BadParameter("Failed to create auth request. Check the auth connector definition for errors. Error: %v", requestInfo.RequestCreateErr)
		}

		info, infoErr := c.GetSSODiagnosticInfo(context.TODO(), raw.Kind, requestInfo.RequestID)

		err = cmd.reportLoginResult(raw.Kind, info, infoErr, loginResponse, loginErr)
		if err != nil {
			return trace.Wrap(err)
		}
	}
}

// TryRun is executed after the CLI parsing is done. The command must
// determine if selectedCommand belongs to it and return match=true
func (cmd *SSOTestCommand) TryRun(selectedCommand string, c auth.ClientI) (match bool, err error) {
	if selectedCommand == cmd.ssoTestCmd.FullCommand() {
		return true, cmd.ssoTestCommand(c)
	}
	return false, nil
}

type AuthRequestInfo struct {
	Config           *client.RedirectorConfig
	RequestID        string
	RequestCreateErr error
}

func (cmd *SSOTestCommand) runSSOLoginFlow(ctx context.Context, protocol string, c auth.ClientI, config *client.RedirectorConfig) (*auth.SSHLoginResponse, error) {
	key, err := client.NewKey()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	proxies, err := c.GetProxies()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(proxies) == 0 {
		return nil, trace.BadParameter("cluster has no proxies.")
	}

	cfg := client.MakeDefaultConfig()
	cfg.WebProxyAddr = proxies[0].GetPublicAddr()

	tc, err := client.NewClient(cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return client.SSHAgentSSOLogin(ctx, client.SSHLoginSSO{
		SSHLogin: client.SSHLogin{
			ProxyAddr:         tc.WebProxyAddr,
			PubKey:            key.Pub,
			TTL:               tc.KeyTTL,
			Insecure:          tc.InsecureSkipVerify,
			Pool:              nil,
			Compatibility:     tc.CertificateFormat,
			RouteToCluster:    tc.SiteName,
			KubernetesCluster: tc.KubernetesCluster,
		},
		ConnectorID: "-sso-test",
		Protocol:    protocol,
		BindAddr:    tc.BindAddr,
		Browser:     tc.Browser,
	}, config)
}

type DiagnosticInfoField struct {
	Present bool
	Show    bool
	Msg     string
}

func (cmd *SSOTestCommand) reportLoginResult(authKind string, diag *types.SSODiagnosticInfo, infoErr error, loginResponse *auth.SSHLoginResponse, loginErr error) (errResult error) {
	success := diag != nil && diag.Success

	// check for errors
	if loginErr != nil || infoErr != nil {
		success = false
	}

	if success {
		fmt.Printf("Success! Logged in as: %v\n", loginResponse.Username)
	} else {
		fmt.Printf("Failure!\n")
		errResult = trace.Errorf("SSO flow failed.")

		if infoErr != nil {
			fmt.Printf("No diagnostic info found. Most likely cause: the request timed out or callback configuration is incorrect. Ensure that user logs within alloted time and IdP configuration is correct.\n Error details: %v\n", trace.UserMessage(infoErr))
			errResult = trace.Wrap(infoErr, "SSO flow failed.")
		}

		if loginErr != nil {
			fmt.Printf("Login error: %v\n", trace.UserMessage(loginErr))
			errResult = trace.Wrap(loginErr, "SSO flow failed.")
		}
	}

	// finish early if there is no diag info to show.
	if diag == nil {
		return errResult
	}

	fields := []DiagnosticInfoField{
		// common
		{
			Present: diag.Error != "",
			Show:    cmd.config.Debug || loginErr == nil,
			Msg:     FormatString("Original error", diag.Error),
		},
		{
			Present: diag.CreateUserParams != nil,
			Show:    true,
			Msg:     formatUserDetails("Authentication details", diag.CreateUserParams),
		},
	}

	// enrich the fields with auth-specific fields
	if getFields, ok := cmd.GetDiagInfoFields[authKind]; ok {
		fields = append(fields, getFields(diag, cmd.config.Debug)...)
	}

	// we want this field last.
	// raw data - debug
	fields = append(fields,
		DiagnosticInfoField{
			Present: true,
			Show:    cmd.config.Debug,
			Msg:     FormatJSON("Raw data", diag),
		})

	const termWidth = 80

	for _, f := range fields {
		if f.Present && f.Show {
			fmt.Println(strings.Repeat("-", termWidth))
			fmt.Println(f.Msg)
		}
	}

	if !cmd.config.Debug {
		fmt.Println(strings.Repeat("-", termWidth))
		fmt.Println("For more details repeat the command with --debug flag.")
	}

	fmt.Println()

	return errResult
}
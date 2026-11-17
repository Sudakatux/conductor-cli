/*
 * Copyright 2026 Conductor Authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package cmd

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/conductor-oss/conductor-cli/internal/cliconfig"
	"github.com/conductor-sdk/conductor-go/sdk/authentication"
	"github.com/conductor-sdk/conductor-go/sdk/settings"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const (
	loginDefaultServer = "https://developer.orkescloud.com"
	loginCallbackPath  = "/callback"
	loginMaxBody       = 16 << 10
)

var (
	loginNoBrowser bool
	loginTimeout   time.Duration
	loginLaunchpad string
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Sign in from the browser and save a profile for an Orkes Conductor server",
	Long: `Sign in to an Orkes Conductor server from your browser and save the access
key it creates as a CLI profile. No key or secret is typed, pasted or printed.

The CLI listens on 127.0.0.1 for one request, opens the server's Launch Pad,
and waits. After you sign in and click Approve, the page creates an access key
for the application "coding-agent" and hands it to the CLI, which saves
~/.conductor-cli/config-<profile>.yaml.

The browser and the CLI must run on the same computer. Otherwise (SSH, a
container), open the printed fallback link and use 'conductor config save'.

Without --server it asks for one, defaulting to Developer Edition
(https://developer.orkescloud.com). The profile defaults to "developer" for
Developer Edition, else the first label of the host (acme for
acme.orkesconductor.com).`,
	Example: `  # Developer Edition
  conductor login

  # Another server, saved as profile "acme"
  conductor login --server https://acme.orkesconductor.com

  # Pick the profile name yourself, then use it
  conductor login --server https://acme.orkesconductor.com --profile prod
  conductor --profile prod workflow list`,
	GroupID: "config",
	Args:    cobra.NoArgs,
	RunE:    runLogin,
}

// loginTarget is a server resolved from user input: the API base the profile
// stores and the UI origin the browser opens.
type loginTarget struct {
	APIURL   string
	UIOrigin string
	Host     string
}

// resolveLoginTarget accepts a root URL, a UI URL or an API URL. A bare root
// gets /api; an existing path is kept as the API base.
func resolveLoginTarget(raw string) (loginTarget, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := neturl.Parse(raw)
	if err != nil || u.Host == "" {
		return loginTarget{}, fmt.Errorf("invalid server URL %q", raw)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return loginTarget{}, fmt.Errorf("server URL must be http or https: %q", raw)
	}
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimRight(u.Path, "/")
	api := origin + "/api"
	if path != "" {
		api = origin + path
	}
	return loginTarget{APIURL: api, UIOrigin: origin, Host: u.Hostname()}, nil
}

// defaultLoginProfile names the profile after the server: "developer" for
// Developer Edition, else the first label of the host.
func defaultLoginProfile(host string) string {
	if host == "developer.orkescloud.com" {
		return "developer"
	}
	label := strings.SplitN(host, ".", 2)[0]
	if label == "" || label == "localhost" || net.ParseIP(host) != nil {
		return "local"
	}
	return label
}

func newLoginState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// loginResult is what the browser hands back: a key, or an error such as
// "denied".
type loginResult struct {
	KeyID   string
	Secret  string
	AppName string
	Err     string
}

// loginCallbackHandler accepts exactly one POST carrying the expected state.
// Origin is not trusted: an https page posting to http://127.0.0.1 is a
// downgrade, so browsers send "Origin: null" under strict-origin referrer
// policies. Only a present, non-null, different origin is rejected.
func loginCallbackHandler(state, uiOrigin string, results chan<- loginResult) http.Handler {
	delivered := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != loginCallbackPath || delivered {
			writeLoginPage(w, http.StatusNotFound, "Not found", "")
			return
		}
		if r.Method != http.MethodPost {
			writeLoginPage(w, http.StatusMethodNotAllowed, "Method not allowed", "")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "null" && origin != uiOrigin {
			writeLoginPage(w, http.StatusForbidden, "Wrong origin", "This request did not come from "+uiOrigin+".")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, loginMaxBody)
		if err := r.ParseForm(); err != nil {
			writeLoginPage(w, http.StatusBadRequest, "Bad request", "")
			return
		}
		got := r.PostForm.Get("state")
		if subtle.ConstantTimeCompare([]byte(got), []byte(state)) != 1 {
			writeLoginPage(w, http.StatusForbidden, "Wrong sign-in link", "This link was not opened by this CLI. Run conductor login again.")
			return
		}
		if e := r.PostForm.Get("error"); e != "" {
			delivered = true
			writeLoginPage(w, http.StatusOK, "Cancelled", "The CLI did not get access. You can close this tab.")
			results <- loginResult{Err: e}
			return
		}
		res := loginResult{
			KeyID:   r.PostForm.Get("keyId"),
			Secret:  r.PostForm.Get("secret"),
			AppName: r.PostForm.Get("appName"),
		}
		if res.KeyID == "" || res.Secret == "" {
			writeLoginPage(w, http.StatusBadRequest, "Missing key", "")
			return
		}
		delivered = true
		writeLoginPage(w, http.StatusOK, "You're connected", "The Conductor CLI is signed in. You can close this tab and go back to your terminal.")
		results <- res
	})
}

func writeLoginPage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>%s</title>
<body style="font:16px system-ui;max-width:520px;margin:15vh auto;padding:0 16px">
<h2>%s</h2><p>%s</p></body>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(body))
}

// writeLoginProfile saves an Enterprise key + secret profile, 0600.
func writeLoginProfile(profileName, apiURL, keyID, keySecret string) (string, error) {
	dir, err := cliconfig.Dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	path := cliconfig.Resolve(dir, profileName)
	data, err := yaml.Marshal(map[string]string{
		"server":      apiURL,
		"server-type": "Enterprise",
		"auth-key":    keyID,
		"auth-secret": keySecret,
	})
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", err
	}
	return path, nil
}

func openBrowser(target string) error {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", target)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		c = exec.Command("xdg-open", target)
	}
	return c.Start()
}

func stdinIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func runLogin(cmd *cobra.Command, _ []string) error {
	// --server is the root's persistent flag; read it directly so a profile
	// or CONDUCTOR_SERVER_URL never stands in for an explicit choice.
	serverInput, _ := cmd.Flags().GetString("server")
	if !cmd.Flags().Changed("server") {
		serverInput = ""
		if stdinIsTerminal() {
			fmt.Printf("Conductor server [%s] (Enter for Developer Edition, or paste your server URL): ", loginDefaultServer)
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			serverInput = strings.TrimSpace(line)
		}
		if serverInput == "" {
			serverInput = loginDefaultServer
		}
	}
	target, err := resolveLoginTarget(serverInput)
	if err != nil {
		return err
	}

	profileName := profile
	if !cmd.Flags().Changed("profile") {
		profileName = defaultLoginProfile(target.Host)
	}
	dir, err := cliconfig.Dir()
	if err != nil {
		return err
	}
	if _, err := os.Stat(cliconfig.Resolve(dir, profileName)); err == nil && !yes {
		if !stdinIsTerminal() {
			return fmt.Errorf("profile %q already exists; pass --yes to replace it or --profile to pick another name", profileName)
		}
		if !confirm(fmt.Sprintf("Profile %q already exists. Replace it?", profileName)) {
			return errors.New("cancelled")
		}
	}

	state, err := newLoginState()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("could not listen on 127.0.0.1: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	results := make(chan loginResult, 1)
	srv := &http.Server{
		Handler:           loginCallbackHandler(state, target.UIOrigin, results),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	q := neturl.Values{}
	q.Set("setup", "cli")
	q.Set("port", fmt.Sprint(port))
	q.Set("state", state)
	if loginLaunchpad != "" {
		q.Set("launchpad", loginLaunchpad)
	}
	approveURL := target.UIOrigin + "/?" + q.Encode()

	fmt.Printf("Signing in to %s (profile %q).\n", target.UIOrigin, profileName)
	if loginNoBrowser {
		fmt.Printf("Open this link in a browser on this computer:\n  %s\n", approveURL)
	} else {
		if err := openBrowser(approveURL); err != nil {
			fmt.Printf("Could not open a browser (%v).\n", err)
		}
		fmt.Printf("If your browser didn't open, visit:\n  %s\n", approveURL)
	}
	fmt.Println("Waiting for you to approve in the browser…")

	var res loginResult
	select {
	case res = <-results:
	case <-time.After(loginTimeout):
		return fmt.Errorf("no answer from the browser after %s.\n"+
			"Is the browser on another computer? Open %s/?setup=key there, then run\n"+
			"  conductor config save --profile %s\n"+
			"and enter %s, Enterprise, and the key id and secret it shows",
			loginTimeout, target.UIOrigin, profileName, target.APIURL)
	case <-cmd.Context().Done():
		return cmd.Context().Err()
	}
	if res.Err != "" {
		return fmt.Errorf("not signed in: %s in the browser", res.Err)
	}

	path, err := writeLoginProfile(profileName, target.APIURL, res.KeyID, res.Secret)
	if err != nil {
		return fmt.Errorf("could not save profile: %w", err)
	}

	// Prove the key works before claiming success. The token is not printed.
	if _, _, err := authentication.GetToken(
		*settings.NewAuthenticationSettings(res.KeyID, res.Secret),
		settings.NewHttpSettings(target.APIURL),
		http.DefaultClient,
	); err != nil {
		return fmt.Errorf("saved %s, but the new key was rejected: %v", path, err)
	}

	app := res.AppName
	if app == "" {
		app = "your application"
	}
	fmt.Printf("✓ Logged in to %s as %s (key %s).\n", target.UIOrigin, app, res.KeyID)
	fmt.Printf("✓ Saved profile %q: %s\n", profileName, path)
	fmt.Printf("\nUse it:            conductor --profile %s workflow list\n", profileName)
	fmt.Println("Add another server: conductor login --server <url>")
	return nil
}

func init() {
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "print the link instead of opening a browser")
	loginCmd.Flags().DurationVar(&loginTimeout, "timeout", 5*time.Minute, "how long to wait for approval in the browser")
	// Loads a Launch Pad PR preview bundle (?launchpad=<url>) until the
	// approval page ships in the published bundle.
	loginCmd.Flags().StringVar(&loginLaunchpad, "launchpad", "", "Launch Pad bundle URL to load (testing)")
	loginCmd.Flags().MarkHidden("launchpad")
	rootCmd.AddCommand(loginCmd)
}

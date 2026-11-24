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
	"fmt"
	"html"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	createAppName  string
)

var createAppCmd = &cobra.Command{
	Use:   "create-app",
	Short: "Create an application access key from the browser and save it as a profile",
	Long: `Sign in to an Orkes Conductor server from your browser, create (or reuse) an
application and an access key for it, and save that key as a CLI profile.
No key or secret is typed, pasted or printed.

The CLI listens on 127.0.0.1 for one request, opens the server's Launch Pad,
and waits. After you sign in and click Approve, the page finds or creates the
application (--name, default "default_app"), creates an access key for it and
hands it to the CLI, which saves ~/.conductor-cli/config-<profile>.yaml.

The browser and the CLI must run on the same computer. Otherwise (SSH, a
container), open the printed fallback link and use 'conductor config save'.

Without --server it asks for one, defaulting to Developer Edition
(https://developer.orkescloud.com). The profile defaults to "developer" for
Developer Edition, else the first label of the host (acme for
acme.orkesconductor.com).`,
	Example: `  # Developer Edition, application "default_app"
  conductor create-app

  # Another server, saved as profile "acme"
  conductor create-app --server https://acme.orkesconductor.com

  # Name the application and the profile yourself, then use it
  conductor create-app --server https://acme.orkesconductor.com --name billing-agent --profile prod
  conductor --profile prod workflow list`,
	GroupID: "config",
	Args:    cobra.NoArgs,
	// Failures are one "create-app failed (<code>): …" line; usage would bury it.
	SilenceUsage: true,
	RunE:         runCreateApp,
}

const defaultAppName = "default_app"

// appNamePattern keeps the name safe in a URL and readable in the UI.
var appNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$`)

func validAppName(name string) bool { return appNamePattern.MatchString(name) }

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

// createAppError is how every create-app failure is reported: one stable first
// line, "create-app failed (<code>): <detail>", optionally followed by hint
// lines. Skills and agents match on the code.
type createAppError struct {
	Code   string
	Detail string
	Hint   string
}

func (e *createAppError) Error() string {
	s := fmt.Sprintf("create-app failed (%s): %s", e.Code, e.Detail)
	if e.Hint != "" {
		s += "\n" + e.Hint
	}
	return s
}

func createAppFail(code, format string, a ...interface{}) error {
	return &createAppError{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// oneLine flattens text from the browser or a server so it can't break the
// single error line, and caps its length.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// loginOutcome is what the CLI tells the browser after it has checked and
// saved the key. The callback holds its response open until it arrives.
type loginOutcome struct {
	status      int
	title, body string
}

// loginResult is what the browser hands back: a key, or an error code such as
// "denied" (with an optional description).
type loginResult struct {
	KeyID     string
	Secret    string
	AppName   string
	Err       string
	ErrDetail string
	reply     chan loginOutcome
}

// finish answers the browser's waiting request. It never blocks: the request
// may already have given up.
func (r loginResult) finish(o loginOutcome) {
	if r.reply == nil {
		return
	}
	select {
	case r.reply <- o:
	default:
	}
}

// loginReplyWait bounds how long the browser's request is held open while the
// CLI checks the key. Past it the page says to look at the terminal.
var loginReplyWait = 45 * time.Second

// loginCallback accepts exactly one POST carrying the expected state.
// Origin is not trusted: an https page posting to http://127.0.0.1 is a
// downgrade, so browsers send "Origin: null" under strict-origin referrer
// policies. Only a present, non-null, different origin is rejected.
//
// A wrong state is answered 403 and otherwise ignored, so an unrelated page
// can't end the wait; it is counted and named if the wait times out.
type loginCallback struct {
	state, uiOrigin string
	results         chan loginResult
	replyWait       time.Duration

	mu         sync.Mutex
	delivered  bool
	wrongState int
}

func loginCallbackHandler(state, uiOrigin string) *loginCallback {
	return &loginCallback{state: state, uiOrigin: uiOrigin, results: make(chan loginResult, 1), replyWait: loginReplyWait}
}

func (c *loginCallback) wrongStateCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wrongState
}

// claim marks the one delivery. Only the first caller gets true.
func (c *loginCallback) claim() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.delivered {
		return false
	}
	c.delivered = true
	return true
}

// deliver hands res to the CLI without blocking; the channel has room for the
// one delivery claim() allows.
func (c *loginCallback) deliver(res loginResult) bool {
	select {
	case c.results <- res:
		return true
	default:
		return false
	}
}

func (c *loginCallback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != loginCallbackPath {
		writeLoginPage(w, http.StatusNotFound, "Not found", "")
		return
	}
	if r.Method != http.MethodPost {
		writeLoginPage(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" && origin != c.uiOrigin {
		writeLoginPage(w, http.StatusForbidden, "Wrong origin", "This request did not come from "+c.uiOrigin+".")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, loginMaxBody)
	if err := r.ParseForm(); err != nil {
		writeLoginPage(w, http.StatusBadRequest, "Bad request", "")
		return
	}
	got := r.PostForm.Get("state")
	if subtle.ConstantTimeCompare([]byte(got), []byte(c.state)) != 1 {
		c.mu.Lock()
		c.wrongState++
		c.mu.Unlock()
		writeLoginPage(w, http.StatusForbidden, "Wrong sign-in link", "This link was not opened by this CLI. Run conductor create-app again.")
		return
	}
	if !c.claim() {
		writeLoginPage(w, http.StatusConflict, "Already answered", "The CLI already got an answer from this page. Check your terminal.")
		return
	}

	if e := r.PostForm.Get("error"); e != "" {
		c.deliver(loginResult{Err: oneLine(e), ErrDetail: oneLine(r.PostForm.Get("error_description"))})
		if e == "denied" {
			writeLoginPage(w, http.StatusOK, "Cancelled", "The CLI did not get access. You can close this tab.")
		} else {
			writeLoginPage(w, http.StatusOK, "Not connected", "The CLI was told the key could not be created. Check your terminal.")
		}
		return
	}
	res := loginResult{
		KeyID:   r.PostForm.Get("keyId"),
		Secret:  r.PostForm.Get("secret"),
		AppName: r.PostForm.Get("appName"),
	}
	if res.KeyID == "" || res.Secret == "" {
		c.deliver(loginResult{Err: "missing_key"})
		writeLoginPage(w, http.StatusBadRequest, "Missing key", "The page sent no key. The CLI stopped; check your terminal.")
		return
	}
	reply := make(chan loginOutcome, 1)
	res.reply = reply
	if !c.deliver(res) {
		writeLoginPage(w, http.StatusServiceUnavailable, "Not delivered", "The CLI is no longer waiting. Check your terminal.")
		return
	}
	// Hold the response until the CLI has checked and saved the key, so the
	// page never says "connected" for a key the server rejected.
	select {
	case o := <-reply:
		writeLoginPage(w, o.status, o.title, o.body)
	case <-time.After(c.replyWait):
		writeLoginPage(w, http.StatusAccepted, "Check your terminal", "The CLI got the key and is still checking it. Your terminal shows the result.")
	case <-r.Context().Done():
	}
}

func writeLoginPage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>%s</title>
<body style="font:16px system-ui;max-width:520px;margin:15vh auto;padding:0 16px">
<h2>%s</h2><p>%s</p></body>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(body))
}

// browserError turns an error the page posted into the CLI's failure.
func browserError(res loginResult) error {
	switch res.Err {
	case "denied":
		return createAppFail("denied", "access was denied in the browser")
	case "missing_key":
		return createAppFail("missing_key", "the browser answered without a key")
	}
	detail := "the browser reported " + strconv.Quote(res.Err)
	if res.ErrDetail != "" {
		detail += ": " + res.ErrDetail
	}
	return createAppFail("approval_failed", "%s", detail)
}

// checkLoginKey exchanges the key for a token at <api>/token. A var so tests
// can stand in for the server.
var checkLoginKey = func(apiURL, keyID, secret string) (err error) {
	// The SDK panics decoding a 2xx text/plain body (reflect SetString on a
	// struct), e.g. when --server points at something that isn't the API.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("unexpected response from %s/token", apiURL)
		}
	}()
	token, _, err := authentication.GetToken(
		*settings.NewAuthenticationSettings(keyID, secret),
		settings.NewHttpSettings(apiURL),
		&http.Client{Timeout: 30 * time.Second},
	)
	if err != nil {
		return err
	}
	if token.Token == "" {
		return fmt.Errorf("%s/token returned no token", apiURL)
	}
	return nil
}

// saveVerifiedProfile checks the key first and only then replaces the profile,
// atomically (temp file in the same directory, 0600, renamed over it). On any
// failure an existing profile is left exactly as it was.
func saveVerifiedProfile(dir, profileName, apiURL, keyID, keySecret string) (string, error) {
	path := cliconfig.Resolve(dir, profileName)
	kept := "no profile was saved"
	if _, err := os.Stat(path); err == nil {
		kept = fmt.Sprintf("the existing profile %q was kept unchanged", profileName)
	}
	if err := checkLoginKey(apiURL, keyID, keySecret); err != nil {
		return "", createAppFail("key_rejected", "the server rejected the new key %s at %s/token: %s; %s",
			keyID, apiURL, oneLine(err.Error()), kept)
	}
	if err := writeProfileAtomic(dir, path, map[string]string{
		"server":      apiURL,
		"server-type": "Enterprise",
		"auth-key":    keyID,
		"auth-secret": keySecret,
	}); err != nil {
		return "", createAppFail("save_failed", "could not write %s: %s; %s", path, oneLine(err.Error()), kept)
	}
	return path, nil
}

func writeProfileAtomic(dir, path string, values map[string]string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := yaml.Marshal(values)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".create-app-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
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

func runCreateApp(cmd *cobra.Command, _ []string) error {
	if !validAppName(createAppName) {
		return createAppFail("invalid_name", "invalid --name %q: use 1-64 letters, digits, spaces, _ . or -, starting with a letter or digit", createAppName)
	}
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
		return createAppFail("invalid_server", "%s", err.Error())
	}

	profileName := profile
	if !cmd.Flags().Changed("profile") {
		profileName = defaultLoginProfile(target.Host)
	}
	dir, err := cliconfig.Dir()
	if err != nil {
		return createAppFail("save_failed", "%s", err.Error())
	}
	if _, err := os.Stat(cliconfig.Resolve(dir, profileName)); err == nil && !yes {
		if !stdinIsTerminal() {
			return createAppFail("profile_exists", "profile %q already exists; pass --yes to replace it or --profile to pick another name", profileName)
		}
		if !confirm(fmt.Sprintf("Profile %q already exists. Replace it?", profileName)) {
			return createAppFail("cancelled", "kept the existing profile %q", profileName)
		}
	}

	state, err := newLoginState()
	if err != nil {
		return createAppFail("listen_failed", "%s", err.Error())
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return createAppFail("listen_failed", "could not listen on 127.0.0.1: %s", err.Error())
	}
	port := ln.Addr().(*net.TCPAddr).Port

	callback := loginCallbackHandler(state, target.UIOrigin)
	srv := &http.Server{
		Handler:           callback,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go srv.Serve(ln)
	defer shutdownLoginServer(srv)

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	q := neturl.Values{}
	q.Set("setup", "cli")
	q.Set("app", createAppName)
	q.Set("port", fmt.Sprint(port))
	q.Set("state", state)
	if loginLaunchpad != "" {
		q.Set("launchpad", loginLaunchpad)
	}
	approveURL := target.UIOrigin + "/?" + q.Encode()

	fmt.Printf("Creating an access key for application %q on %s (profile %q).\n", createAppName, target.UIOrigin, profileName)
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
	case res = <-callback.results:
	case <-time.After(loginTimeout):
		detail := fmt.Sprintf("no answer from the browser after %s", loginTimeout)
		if n := callback.wrongStateCount(); n > 0 {
			detail += fmt.Sprintf(" (%d callback(s) with the wrong state were ignored)", n)
		}
		return &createAppError{Code: "timeout", Detail: detail, Hint: fmt.Sprintf(
			"Is the browser on another computer? Open %s/?setup=key there, then run\n"+
				"  conductor config save --profile %s\n"+
				"and enter %s, Enterprise, and the key id and secret it shows",
			target.UIOrigin, profileName, target.APIURL)}
	case <-ctx.Done():
		return createAppFail("interrupted", "stopped before the browser answered")
	}
	if res.Err != "" {
		return browserError(res)
	}

	path, err := saveVerifiedProfile(dir, profileName, target.APIURL, res.KeyID, res.Secret)
	if err != nil {
		res.finish(loginOutcome{http.StatusBadGateway, "Not connected",
			"The server rejected the new key or the CLI could not save it. Check your terminal."})
		return err
	}
	res.finish(loginOutcome{http.StatusOK, "You're connected",
		"The Conductor CLI saved the key. You can close this tab and go back to your terminal."})

	app := res.AppName
	if app == "" {
		app = createAppName
	}
	fmt.Printf("✓ Logged in to %s as %s (key %s).\n", target.UIOrigin, app, res.KeyID)
	fmt.Printf("✓ Saved profile %q: %s\n", profileName, path)
	fmt.Printf("\nUse it:            conductor --profile %s workflow list\n", profileName)
	fmt.Println("Add another server: conductor create-app --server <url>")
	return nil
}

// shutdownLoginServer gives an in-flight reply a moment to reach the browser,
// then closes everything. It never waits longer than that.
func shutdownLoginServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		srv.Close()
	}
}

func init() {
	createAppCmd.Flags().StringVar(&createAppName, "name", defaultAppName, "application to create or reuse (letters, digits, space, _ . -)")
	createAppCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "print the link instead of opening a browser")
	createAppCmd.Flags().DurationVar(&loginTimeout, "timeout", 5*time.Minute, "how long to wait for approval in the browser")
	// Loads a Launch Pad PR preview bundle (?launchpad=<url>) until the
	// approval page ships in the published bundle.
	createAppCmd.Flags().StringVar(&loginLaunchpad, "launchpad", "", "Launch Pad bundle URL to load (testing)")
	createAppCmd.Flags().MarkHidden("launchpad")
	rootCmd.AddCommand(createAppCmd)
}

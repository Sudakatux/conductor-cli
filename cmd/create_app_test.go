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
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestResolveLoginTarget(t *testing.T) {
	cases := []struct{ in, api, ui string }{
		{"https://developer.orkescloud.com", "https://developer.orkescloud.com/api", "https://developer.orkescloud.com"},
		{"https://developer.orkescloud.com/", "https://developer.orkescloud.com/api", "https://developer.orkescloud.com"},
		{"acme.orkesconductor.com", "https://acme.orkesconductor.com/api", "https://acme.orkesconductor.com"},
		{"https://acme.orkesconductor.com/api", "https://acme.orkesconductor.com/api", "https://acme.orkesconductor.com"},
		{"https://host.example/conductor/api/", "https://host.example/conductor/api", "https://host.example"},
	}
	for _, c := range cases {
		got, err := resolveLoginTarget(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got.APIURL != c.api || got.UIOrigin != c.ui {
			t.Errorf("%s: got api=%s ui=%s, want api=%s ui=%s", c.in, got.APIURL, got.UIOrigin, c.api, c.ui)
		}
	}
	if _, err := resolveLoginTarget("ftp://x"); err == nil {
		t.Error("ftp scheme should be rejected")
	}
}

func TestDefaultLoginProfile(t *testing.T) {
	cases := map[string]string{
		"developer.orkescloud.com":        "developer",
		"acme.orkesconductor.com":         "acme",
		"jsm-test-ino.orkesconductor.net": "jsm-test-ino",
		"localhost":                       "local",
		"127.0.0.1":                       "local",
	}
	for host, want := range cases {
		if got := defaultLoginProfile(host); got != want {
			t.Errorf("%s: got %s, want %s", host, got, want)
		}
	}
}

func postCallback(h http.Handler, origin string, form neturl.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, loginCallbackPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLoginCallback(t *testing.T) {
	const ui = "https://acme.orkesconductor.com"
	good := neturl.Values{"state": {"s3cr3t-state"}, "keyId": {"k1"}, "secret": {"v1"}, "appName": {"coding-agent"}}

	t.Run("wrong state is rejected and counted", func(t *testing.T) {
		h := loginCallbackHandler("s3cr3t-state", ui)
		bad := neturl.Values{"state": {"nope"}, "keyId": {"k"}, "secret": {"s"}}
		if rec := postCallback(h, ui, bad); rec.Code != http.StatusForbidden {
			t.Fatalf("got %d", rec.Code)
		}
		if len(h.results) != 0 {
			t.Fatal("no result should be delivered")
		}
		if n := h.wrongStateCount(); n != 1 {
			t.Fatalf("wrong state count = %d", n)
		}
	})

	t.Run("another site's origin is rejected", func(t *testing.T) {
		h := loginCallbackHandler("s3cr3t-state", ui)
		if rec := postCallback(h, "https://evil.example", good); rec.Code != http.StatusForbidden {
			t.Fatalf("got %d", rec.Code)
		}
	})

	t.Run("GET is rejected", func(t *testing.T) {
		h := loginCallbackHandler("s3cr3t-state", ui)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, loginCallbackPath, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("got %d", rec.Code)
		}
	})

	// https -> http://127.0.0.1 is a downgrade: browsers send Origin: null.
	for _, origin := range []string{"null", "", ui} {
		t.Run("origin "+origin+" delivers once and waits for the outcome", func(t *testing.T) {
			h := loginCallbackHandler("s3cr3t-state", ui)
			done := make(chan *httptest.ResponseRecorder)
			go func() { done <- postCallback(h, origin, good) }()
			res := <-h.results
			if res.KeyID != "k1" || res.Secret != "v1" || res.AppName != "coding-agent" {
				t.Fatalf("got %+v", res)
			}
			res.finish(loginOutcome{http.StatusOK, "You're connected", "ok"})
			if rec := <-done; rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "connected") {
				t.Fatalf("got %d %s", rec.Code, rec.Body)
			}
			if rec := postCallback(h, origin, good); rec.Code != http.StatusConflict {
				t.Fatalf("second delivery: got %d", rec.Code)
			}
		})
	}

	t.Run("a rejected key is shown in the browser, not success", func(t *testing.T) {
		h := loginCallbackHandler("s3cr3t-state", ui)
		done := make(chan *httptest.ResponseRecorder)
		go func() { done <- postCallback(h, "null", good) }()
		res := <-h.results
		res.finish(loginOutcome{http.StatusBadGateway, "Not connected", "rejected"})
		rec := <-done
		if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "You&#39;re connected") {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("the browser is not held past the reply wait", func(t *testing.T) {
		h := loginCallbackHandler("s3cr3t-state", ui)
		h.replyWait = 20 * time.Millisecond
		rec := postCallback(h, "null", good) // nobody calls finish
		if rec.Code != http.StatusAccepted || strings.Contains(rec.Body.String(), "connected") {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
		res := <-h.results
		res.finish(loginOutcome{}) // a late finish must not block
	})

	t.Run("denied is reported", func(t *testing.T) {
		h := loginCallbackHandler("s3cr3t-state", ui)
		postCallback(h, "null", neturl.Values{"state": {"s3cr3t-state"}, "error": {"denied"}})
		res := <-h.results
		if res.Err != "denied" {
			t.Fatalf("got %+v", res)
		}
		if got := browserError(res).Error(); got != "create-app failed (denied): access was denied in the browser" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("a failure in the page is reported with its description", func(t *testing.T) {
		h := loginCallbackHandler("s3cr3t-state", ui)
		postCallback(h, "null", neturl.Values{"state": {"s3cr3t-state"}, "error": {"key_creation_failed"},
			"error_description": {"403 Forbidden\nnot allowed"}})
		got := browserError(<-h.results).Error()
		want := `create-app failed (approval_failed): the browser reported "key_creation_failed": 403 Forbidden not allowed`
		if got != want {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("the right state but no key ends the wait", func(t *testing.T) {
		h := loginCallbackHandler("s3cr3t-state", ui)
		if rec := postCallback(h, "null", neturl.Values{"state": {"s3cr3t-state"}}); rec.Code != http.StatusBadRequest {
			t.Fatalf("got %d", rec.Code)
		}
		if got := browserError(<-h.results).Error(); !strings.HasPrefix(got, "create-app failed (missing_key): ") {
			t.Fatalf("got %q", got)
		}
	})
}

// Two approvals racing (a double-clicked Approve): exactly one is delivered,
// the other is told so at once, and nothing blocks. Run with -race.
func TestLoginCallbackConcurrentDoublePost(t *testing.T) {
	const ui = "https://acme.orkesconductor.com"
	good := neturl.Values{"state": {"s3cr3t-state"}, "keyId": {"k1"}, "secret": {"v1"}}
	for i := 0; i < 50; i++ {
		h := loginCallbackHandler("s3cr3t-state", ui)
		var wg sync.WaitGroup
		codes := make(chan int, 2)
		for j := 0; j < 2; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes <- postCallback(h, "null", good).Code
			}()
		}
		select {
		case res := <-h.results:
			res.finish(loginOutcome{http.StatusOK, "You're connected", ""})
		case <-time.After(5 * time.Second):
			t.Fatal("no delivery")
		}
		finished := make(chan struct{})
		go func() { wg.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Fatal("a callback request hung")
		}
		close(codes)
		got := map[int]int{}
		for c := range codes {
			got[c]++
		}
		if got[http.StatusOK] != 1 || got[http.StatusConflict] != 1 {
			t.Fatalf("codes = %v", got)
		}
		if len(h.results) != 0 {
			t.Fatal("a second result leaked into the channel")
		}
	}
}

// The login server shuts down promptly even with a request still held open.
func TestShutdownLoginServerNeverHangs(t *testing.T) {
	h := loginCallbackHandler("s3cr3t-state", "https://x")
	h.replyWait = time.Hour
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	go http.PostForm("http://"+ln.Addr().String()+loginCallbackPath,
		neturl.Values{"state": {"s3cr3t-state"}, "keyId": {"k"}, "secret": {"s"}})
	<-h.results // delivered; nobody ever calls finish
	done := make(chan struct{})
	go func() { shutdownLoginServer(srv); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown hung")
	}
}

func withLoginKeyCheck(t *testing.T, f func(apiURL, keyID, secret string) error) {
	old := checkLoginKey
	checkLoginKey = f
	t.Cleanup(func() { checkLoginKey = old })
}

func TestSaveVerifiedProfileRejectedKeyKeepsExistingProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config-acme.yaml")
	original := []byte("server: https://acme.orkesconductor.com/api\nauth-key: old\nauth-secret: old-secret\n# hand edited\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	withLoginKeyCheck(t, func(string, string, string) error { return errors.New("{\"message\": \"bad\"}\n") })

	_, err := saveVerifiedProfile(dir, "acme", "https://acme.orkesconductor.com/api", "k2", "bad")
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "create-app failed (key_rejected): ") || !strings.Contains(msg, `the existing profile "acme" was kept unchanged`) {
		t.Fatalf("got %q", msg)
	}
	if strings.Contains(msg, "\n") {
		t.Fatalf("error must be one line: %q", msg)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, original) {
		t.Fatalf("profile changed:\n%s", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

func TestSaveVerifiedProfileRejectedKeyWithoutProfile(t *testing.T) {
	dir := t.TempDir()
	withLoginKeyCheck(t, func(string, string, string) error { return errors.New("401") })
	_, err := saveVerifiedProfile(dir, "acme", "https://a/api", "k", "s")
	if err == nil || !strings.Contains(err.Error(), "no profile was saved") {
		t.Fatalf("got %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files written: %v", entries)
	}
}

func TestSaveVerifiedProfileReplacesAtomically0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config-acme.yaml")
	if err := os.WriteFile(path, []byte("auth-secret: old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	checked := false
	withLoginKeyCheck(t, func(api, id, secret string) error {
		checked = true
		if api != "https://a/api" || id != "k" || secret != "s" {
			t.Errorf("checked %s %s %s", api, id, secret)
		}
		return nil
	})
	got, err := saveVerifiedProfile(dir, "acme", "https://a/api", "k", "s")
	if err != nil || got != path || !checked {
		t.Fatalf("got %q %v checked=%v", got, err, checked)
	}
	fi, _ := os.Stat(path)
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	for _, want := range []string{"server: https://a/api", "server-type: Enterprise", "auth-key: k", "auth-secret: s"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %q in\n%s", want, data)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

// The real check posts the key to <api>/token.
func TestCheckLoginKeyAgainstServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path == "/text/token":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("hello"))
		case r.URL.Path == "/empty/token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{}`))
		case r.URL.Path != "/api/token" || !strings.Contains(string(body), `"keySecret":"good"`):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message":"bad key"}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"token":"t"}`))
		}
	}))
	defer srv.Close()
	if err := checkLoginKey(srv.URL+"/api", "k", "good"); err != nil {
		t.Fatalf("good key: %v", err)
	}
	if err := checkLoginKey(srv.URL+"/api", "k", "bad"); err == nil {
		t.Fatal("bad key accepted")
	}
	// Not the API: no panic, no false success.
	if err := checkLoginKey(srv.URL+"/text", "k", "good"); err == nil {
		t.Fatal("text/plain response accepted")
	}
	if err := checkLoginKey(srv.URL+"/empty", "k", "good"); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestCreateAppErrorFormat(t *testing.T) {
	e := &createAppError{Code: "timeout", Detail: "no answer from the browser after 5m0s", Hint: "hint"}
	if got := e.Error(); got != "create-app failed (timeout): no answer from the browser after 5m0s\nhint" {
		t.Fatalf("got %q", got)
	}
	if got := oneLine("a\n  b\tc"); got != "a b c" {
		t.Fatalf("got %q", got)
	}
}

func TestValidAppName(t *testing.T) {
	for _, ok := range []string{"default_app", "coding-agent", "Billing Agent 2", "a", "x.y-z_1"} {
		if !validAppName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", " lead", "-dash", "a/b", "a&b", "a?b", strings.Repeat("a", 65), "tab\tname"} {
		if validAppName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestCreateAppCommandShape(t *testing.T) {
	if createAppCmd.Use != "create-app" {
		t.Fatalf("Use = %q", createAppCmd.Use)
	}
	f := createAppCmd.Flags().Lookup("name")
	if f == nil || f.DefValue != defaultAppName || defaultAppName != "default_app" {
		t.Fatalf("--name flag default: %+v", f)
	}
	if !localOnlyCommands["create-app"] || localOnlyCommands["login"] {
		t.Fatal("create-app must be local-only and login gone")
	}
	// create-app's failures are one line; other commands keep their usage.
	if !createAppCmd.SilenceUsage || rootCmd.SilenceUsage || workflowCmd.SilenceUsage {
		t.Fatal("SilenceUsage must be set on create-app only")
	}
}

func contextJSServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/context.js" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

const noLaunchpadLine = "create-app failed (no_launchpad): create-app is only available on Orkes Developer Edition (developer.orkescloud.com)"

func TestCheckDeveloperEdition(t *testing.T) {
	pass := []struct{ name, body string }{
		{"boolean true", `window.conductor = {"AUTH_DOMAIN": "x", "PLAYGROUND": true, "OTHER": 1};`},
		{"string true", `window.conductor = {"PLAYGROUND": "true"};`},
		{"bare key, spaces", "window.conductor = {\n  PLAYGROUND :  true,\n};"},
		{"single quotes", `window.conductor = {'PLAYGROUND': 'true'};`},
	}
	for _, c := range pass {
		t.Run(c.name, func(t *testing.T) {
			srv := contextJSServer(t, http.StatusOK, c.body)
			if err := checkDeveloperEdition(srv.URL); err != nil {
				t.Fatalf("got %v", err)
			}
		})
	}

	// PLAYGROUND present but not true: the plain line, no reason.
	for _, body := range []string{
		`window.conductor = {"PLAYGROUND": false};`,
		`window.conductor = {"PLAYGROUND": "false"};`,
		`window.conductor = {"PLAYGROUND": ""};`,
		`window.conductor = {"PLAYGROUND": "truer"};`,
	} {
		t.Run("not true: "+body, func(t *testing.T) {
			srv := contextJSServer(t, http.StatusOK, body)
			err := checkDeveloperEdition(srv.URL)
			if err == nil || err.Error() != noLaunchpadLine {
				t.Fatalf("got %v", err)
			}
		})
	}

	unconfirmed := func(t *testing.T, err error, reason string) {
		t.Helper()
		if err == nil {
			t.Fatal("expected no_launchpad")
		}
		msg := err.Error()
		if !strings.HasPrefix(msg, noLaunchpadLine+"; couldn't confirm this is Developer Edition: ") ||
			!strings.Contains(msg, reason) || strings.Contains(msg, "\n") {
			t.Fatalf("got %q", msg)
		}
	}
	t.Run("key missing", func(t *testing.T) {
		srv := contextJSServer(t, http.StatusOK, `window.conductor = {"NOT_PLAYGROUND": true, "PLAYGROUND_X": true};`)
		unconfirmed(t, checkDeveloperEdition(srv.URL), "has no PLAYGROUND setting")
	})
	t.Run("404", func(t *testing.T) {
		srv := contextJSServer(t, http.StatusNotFound, `{"PLAYGROUND": true}`)
		unconfirmed(t, checkDeveloperEdition(srv.URL), "returned 404")
	})
	t.Run("server error", func(t *testing.T) {
		srv := contextJSServer(t, http.StatusInternalServerError, "")
		unconfirmed(t, checkDeveloperEdition(srv.URL), "returned 500")
	})
	t.Run("network error", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		addr := srv.URL
		srv.Close()
		unconfirmed(t, checkDeveloperEdition(addr), "could not read "+addr+"/context.js")
	})
	t.Run("unreadable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			io.WriteString(w, `{"PLAY`) // then the connection drops
		}))
		defer srv.Close()
		unconfirmed(t, checkDeveloperEdition(srv.URL), "could not read")
	})
	t.Run("times out", func(t *testing.T) {
		old := developerEditionTimeout
		developerEditionTimeout = 50 * time.Millisecond
		t.Cleanup(func() { developerEditionTimeout = old })
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
		defer srv.Close()
		defer close(release)
		unconfirmed(t, checkDeveloperEdition(srv.URL), "could not read")
	})
}

// runCreateAppAgainst runs create-app against server with the listener and the
// browser replaced by recorders. It returns the error and whether each started.
func runCreateAppAgainst(t *testing.T, server string, extra map[string]string) (err error, listened, opened bool) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	oldListen, oldOpen, oldTimeout, oldLaunchpad := loginListen, openBrowser, loginTimeout, loginLaunchpad
	t.Cleanup(func() {
		loginListen, openBrowser, loginTimeout, loginLaunchpad = oldListen, oldOpen, oldTimeout, oldLaunchpad
	})
	loginListen = func(network, addr string) (net.Listener, error) {
		listened = true
		return net.Listen(network, addr)
	}
	openBrowser = func(string) error { opened = true; return nil }
	loginTimeout = 10 * time.Millisecond
	loginLaunchpad = extra["launchpad"]

	c := &cobra.Command{Use: "create-app", RunE: runCreateApp}
	c.SetContext(context.Background())
	c.Flags().String("server", "", "")
	c.Flags().String("profile", "", "")
	if err := c.Flags().Set("server", server); err != nil {
		t.Fatal(err)
	}
	return runCreateApp(c, nil), listened, opened
}

func TestCreateAppStopsBeforeListenerAndBrowserWithoutDeveloperEdition(t *testing.T) {
	for name, body := range map[string]string{
		"false":   `window.conductor = {"PLAYGROUND": false};`,
		"missing": `window.conductor = {};`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := contextJSServer(t, http.StatusOK, body)
			// --launchpad must not bypass the check.
			err, listened, opened := runCreateAppAgainst(t, srv.URL+"/api", map[string]string{"launchpad": "http://localhost:4321/launchpad.js"})
			if err == nil || !strings.HasPrefix(err.Error(), noLaunchpadLine) {
				t.Fatalf("got %v", err)
			}
			if listened || opened {
				t.Fatalf("listened=%v opened=%v", listened, opened)
			}
		})
	}
}

func TestCreateAppContinuesOnDeveloperEdition(t *testing.T) {
	srv := contextJSServer(t, http.StatusOK, `window.conductor = {"PLAYGROUND": "true"};`)
	err, listened, opened := runCreateAppAgainst(t, srv.URL, nil)
	// It gets as far as waiting for the browser, which never answers here.
	if err == nil || !strings.HasPrefix(err.Error(), "create-app failed (timeout): ") {
		t.Fatalf("got %v", err)
	}
	if !listened || !opened {
		t.Fatalf("listened=%v opened=%v", listened, opened)
	}
}

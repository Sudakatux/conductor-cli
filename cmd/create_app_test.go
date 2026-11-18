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
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"testing"
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

	t.Run("wrong state is rejected", func(t *testing.T) {
		results := make(chan loginResult, 1)
		h := loginCallbackHandler("s3cr3t-state", ui, results)
		bad := neturl.Values{"state": {"nope"}, "keyId": {"k"}, "secret": {"s"}}
		if rec := postCallback(h, ui, bad); rec.Code != http.StatusForbidden {
			t.Fatalf("got %d", rec.Code)
		}
		if len(results) != 0 {
			t.Fatal("no result should be delivered")
		}
	})

	t.Run("another site's origin is rejected", func(t *testing.T) {
		results := make(chan loginResult, 1)
		h := loginCallbackHandler("s3cr3t-state", ui, results)
		if rec := postCallback(h, "https://evil.example", good); rec.Code != http.StatusForbidden {
			t.Fatalf("got %d", rec.Code)
		}
	})

	t.Run("GET is rejected", func(t *testing.T) {
		h := loginCallbackHandler("s3cr3t-state", ui, make(chan loginResult, 1))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, loginCallbackPath, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("got %d", rec.Code)
		}
	})

	// https -> http://127.0.0.1 is a downgrade: browsers send Origin: null.
	for _, origin := range []string{"null", "", ui} {
		t.Run("origin "+origin+" delivers once", func(t *testing.T) {
			results := make(chan loginResult, 1)
			h := loginCallbackHandler("s3cr3t-state", ui, results)
			if rec := postCallback(h, origin, good); rec.Code != http.StatusOK {
				t.Fatalf("got %d", rec.Code)
			}
			res := <-results
			if res.KeyID != "k1" || res.Secret != "v1" || res.AppName != "coding-agent" {
				t.Fatalf("got %+v", res)
			}
			if rec := postCallback(h, origin, good); rec.Code != http.StatusNotFound {
				t.Fatalf("second delivery: got %d", rec.Code)
			}
		})
	}

	t.Run("denied is reported", func(t *testing.T) {
		results := make(chan loginResult, 1)
		h := loginCallbackHandler("s3cr3t-state", ui, results)
		postCallback(h, "null", neturl.Values{"state": {"s3cr3t-state"}, "error": {"denied"}})
		if res := <-results; res.Err != "denied" {
			t.Fatalf("got %+v", res)
		}
	})
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
}

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
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

const anthropicDef = `{"name":"Anthropic","type":"anthropic","category":"AI_MODEL","configuration":[
 {"fieldName":"api_key","fieldType":"PASSWORD","optional":false},
 {"fieldName":"endpoint","fieldType":"TEXT","optional":false},
 {"fieldName":"version","fieldType":"TEXT","optional":true}]}`

const bedrockDef = `{"name":"Bedrock","type":"aws_bedrock_anthropic","category":"AI_MODEL","configuration":[
 {"fieldName":"connectionType","fieldType":"DROPDOWN","valueOptions":[
   {"label":"Current Conductor Role","value":"CONDUCTOR_ROLE"},
   {"label":"Assume External Role","value":"EXTERNAL_ROLE"},
   {"label":"Access Key/Secret","value":"ACCESS_KEY"}]},
 {"fieldName":"region","fieldType":"TEXT"},
 {"fieldName":"user","fieldType":"TEXT","dependsOn":[{"fieldName":"connectionType","value":"ACCESS_KEY"}]},
 {"fieldName":"api_key","fieldType":"PASSWORD","dependsOn":[{"fieldName":"connectionType","value":"ACCESS_KEY"}]},
 {"fieldName":"roleArn","fieldType":"TEXT","dependsOn":[{"fieldName":"connectionType","value":"EXTERNAL_ROLE"}]},
 {"fieldName":"externalId","fieldType":"PASSWORD","dependsOn":[{"fieldName":"connectionType","value":"EXTERNAL_ROLE"}]}]}`

func mustDef(t *testing.T, s string) integrationDef {
	t.Helper()
	var d integrationDef
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// fakePrompter answers lines from input and secrets from secrets, recording
// every prompt it shows.
func fakePrompter(input string, secrets ...string) (*prompter, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &prompter{
		in:  bufio.NewReader(strings.NewReader(input)),
		out: out,
		readSecret: func(prompt string) (string, error) {
			out.WriteString(prompt)
			s := secrets[0]
			secrets = secrets[1:]
			return s, nil
		},
		readFile: func(string) ([]byte, error) { return []byte("{}"), nil },
	}, out
}

func TestCollectAnthropic(t *testing.T) {
	p, out := fakePrompter("\n", "sk-ant-secret")
	cfg, err := collectIntegrationConfig(mustDef(t, anthropicDef), nil, false, p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg["api_key"] != "sk-ant-secret" || cfg["endpoint"] != "https://api.anthropic.com" {
		t.Fatalf("got %v", cfg)
	}
	if _, asked := cfg["version"]; asked || strings.Contains(out.String(), "version") {
		t.Fatal("optional field asked without --advanced")
	}
	if strings.Contains(out.String(), "sk-ant-secret") {
		t.Fatal("secret echoed")
	}
}

func TestCollectBedrockFollowsDependsOn(t *testing.T) {
	// choose 2 (EXTERNAL_ROLE), region, roleArn; externalId is hidden
	p, out := fakePrompter("2\nus-east-1\narn:aws:iam::1:role/x\n", "ext-id")
	cfg, err := collectIntegrationConfig(mustDef(t, bedrockDef), nil, false, p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{"connectionType": "EXTERNAL_ROLE", "region": "us-east-1",
		"roleArn": "arn:aws:iam::1:role/x", "externalId": "ext-id"}
	for k, v := range want {
		if cfg[k] != v {
			t.Fatalf("%s: got %v want %v (all %v)", k, cfg[k], v, cfg)
		}
	}
	if _, ok := cfg["user"]; ok || strings.Contains(out.String(), "api_key") {
		t.Fatal("ACCESS_KEY fields asked for EXTERNAL_ROLE")
	}
}

func TestSecretPresetRefused(t *testing.T) {
	p, _ := fakePrompter("")
	if _, err := collectIntegrationConfig(mustDef(t, anthropicDef), map[string]string{"api_key": "x"}, false, p); err == nil {
		t.Fatal("a secret passed with --set must be refused")
	}
	if _, err := collectIntegrationConfig(mustDef(t, anthropicDef), map[string]string{"nope": "x"}, false, p); err == nil {
		t.Fatal("an unknown field must be refused")
	}
}

func TestParseModelChoice(t *testing.T) {
	av := []string{"a", "b", "c"}
	if got, _ := parseModelChoice("", av); len(got) != 3 {
		t.Fatal("empty = all")
	}
	if got, _ := parseModelChoice("1, 3", av); strings.Join(got, ",") != "a,c" {
		t.Fatalf("got %v", got)
	}
	if got, _ := parseModelChoice("none", av); got != nil {
		t.Fatal("none = nothing")
	}
	if _, err := parseModelChoice("4", av); err == nil {
		t.Fatal("out of range accepted")
	}
}

type recorded struct {
	method, path string
	body         map[string]interface{}
}

func fakeServer(t *testing.T, createStatus int) (*httptest.Server, *[]recorded) {
	t.Helper()
	var calls []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Authorization") != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]interface{}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		calls = append(calls, recorded{r.Method, r.URL.Path, body})
		switch {
		case r.URL.Path == "/api/integrations/def":
			io.WriteString(w, "["+anthropicDef+"]")
		case r.Method == http.MethodGet && r.URL.Path == "/api/integrations/provider/anthropic":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/api/integrations/provider/anthropic":
			w.WriteHeader(createStatus)
		case r.URL.Path == "/api/integrations/provider/anthropic/integration/all":
			io.WriteString(w, `["claude-b","claude-a"]`)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/integrations/provider/anthropic/integration/"):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func withServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	oldURL := url
	url = srv.URL + "/api"
	viper.Set("auth-token", "test-token")
	t.Cleanup(func() {
		url = oldURL
		viper.Set("auth-token", "")
		integrationName, integrationModels, integrationSet, integrationShareWith = "", nil, nil, ""
	})
}

func TestRunIntegrationAdd(t *testing.T) {
	srv, calls := fakeServer(t, http.StatusOK)
	withServer(t, srv)

	// Enter = default endpoint; "2" picks claude-b from the sorted list [claude-a, claude-b]
	p, out := fakePrompter("\n2\n", "sk-ant-secret")
	if err := runIntegrationAdd(p, "anthropic"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var create, model *recorded
	for i, c := range *calls {
		if c.method == http.MethodPost && c.path == "/api/integrations/provider/anthropic" {
			create = &(*calls)[i]
		}
		if c.method == http.MethodPost && strings.HasSuffix(c.path, "/integration/claude-b") {
			model = &(*calls)[i]
		}
	}
	if create == nil || model == nil {
		t.Fatalf("missing calls: %+v", *calls)
	}
	cfg := create.body["configuration"].(map[string]interface{})
	if create.body["type"] != "anthropic" || cfg["api_key"] != "sk-ant-secret" || cfg["endpoint"] != "https://api.anthropic.com" {
		t.Fatalf("create body: %v", create.body)
	}
	if strings.Contains(out.String(), "sk-ant-secret") {
		t.Fatal("secret printed")
	}
	if !strings.Contains(out.String(), `"llmProvider": "anthropic", "model": "claude-b"`) {
		t.Fatalf("summary missing:\n%s", out)
	}
}

func TestRunIntegrationAddForbiddenPointsToBrowser(t *testing.T) {
	srv, _ := fakeServer(t, http.StatusForbidden)
	withServer(t, srv)
	p, _ := fakePrompter("\n", "sk")
	err := runIntegrationAdd(p, "anthropic")
	if err == nil || !strings.Contains(err.Error(), "/integrations/addIntegration?search=ant") {
		t.Fatalf("got %v", err)
	}
}

func TestUnknownModelRefused(t *testing.T) {
	srv, _ := fakeServer(t, http.StatusOK)
	withServer(t, srv)
	integrationModels = []string{"claude-z"}
	p, _ := fakePrompter("\n", "sk")
	if err := runIntegrationAdd(p, "anthropic"); err == nil || !strings.Contains(err.Error(), "not offered") {
		t.Fatalf("got %v", err)
	}
}

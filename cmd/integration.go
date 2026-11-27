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
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Integrations are Orkes (Enterprise) only. Field definitions come from the
// server (GET /integrations/def), so every provider type is prompted for the
// same way: PASSWORD and FILE fields are secret and are only ever read from a
// hidden prompt or a local file — never from flags, environment or output.

type integrationDependsOn struct {
	FieldName string `json:"fieldName"`
	Value     string `json:"value"`
}

type integrationField struct {
	FieldName    string `json:"fieldName"`
	FieldType    string `json:"fieldType"`
	Label        string `json:"label"`
	Description  string `json:"description"`
	DefaultValue string `json:"defaultValue"`
	Optional     bool   `json:"optional"`
	ValueOptions []struct {
		Label string `json:"label"`
		Value string `json:"value"`
	} `json:"valueOptions"`
	DependsOn []integrationDependsOn `json:"dependsOn"`
}

type integrationDef struct {
	Name          string             `json:"name"`
	Type          string             `json:"type"`
	Category      string             `json:"category"`
	Configuration []integrationField `json:"configuration"`
}

type integrationProvider struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type integrationModel struct {
	Api         string `json:"api"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// knownFieldDefaults fills in public endpoints the server's definitions leave
// blank, so the common case is Enter.
var knownFieldDefaults = map[string]string{
	"anthropic.endpoint": "https://api.anthropic.com",
	"openai.endpoint":    "https://api.openai.com/v1",
}

func isSecretField(f integrationField) bool {
	return f.FieldType == "PASSWORD" || f.FieldType == "FILE"
}

func fieldLabel(f integrationField) string {
	if f.Label != "" {
		return f.Label
	}
	return f.FieldName
}

func dependsSatisfied(f integrationField, cfg map[string]interface{}) bool {
	for _, d := range f.DependsOn {
		if fmt.Sprint(cfg[d.FieldName]) != d.Value {
			return false
		}
	}
	return true
}

// prompter reads answers. Secrets go through readSecret, which never echoes.
type prompter struct {
	in         *bufio.Reader
	out        io.Writer
	readSecret func(prompt string) (string, error)
	readFile   func(path string) ([]byte, error)
}

func terminalPrompter() *prompter {
	return &prompter{
		in:  bufio.NewReader(os.Stdin),
		out: os.Stdout,
		readSecret: func(prompt string) (string, error) {
			fmt.Fprint(os.Stdout, prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stdout)
			return string(b), err
		},
		readFile: os.ReadFile,
	}
}

func (p *prompter) line(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	s, err := p.in.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		return strings.TrimSpace(s), err
	}
	return strings.TrimSpace(s), nil
}

// collectIntegrationConfig asks for each field the definition needs, in order.
// preset holds non-secret values from --set; a secret there is refused.
func collectIntegrationConfig(def integrationDef, preset map[string]string, advanced bool, p *prompter) (map[string]interface{}, error) {
	byName := map[string]integrationField{}
	for _, f := range def.Configuration {
		byName[f.FieldName] = f
	}
	for k := range preset {
		f, ok := byName[k]
		if !ok {
			return nil, fmt.Errorf("%s has no field %q", def.Type, k)
		}
		if isSecretField(f) {
			return nil, fmt.Errorf("%s is secret: it is asked for with a hidden prompt, never passed with --set", k)
		}
	}

	cfg := map[string]interface{}{}
	for _, f := range def.Configuration {
		if !dependsSatisfied(f, cfg) {
			continue
		}
		if v, ok := preset[f.FieldName]; ok {
			cfg[f.FieldName] = v
			continue
		}
		if f.Optional && !advanced {
			continue
		}
		label := fieldLabel(f)
		opt := ""
		if f.Optional {
			opt = " (optional, Enter to skip)"
		}
		for attempt := 0; ; attempt++ {
			if attempt == 3 {
				return nil, fmt.Errorf("%s is required", label)
			}
			var val string
			var err error
			switch f.FieldType {
			case "PASSWORD":
				val, err = p.readSecret(fmt.Sprintf("%s%s (hidden): ", label, opt))
				val = strings.TrimSpace(val)
			case "FILE":
				var path string
				path, err = p.line(fmt.Sprintf("%s — path to the file%s: ", label, opt))
				if err == nil && path != "" {
					var b []byte
					if b, err = p.readFile(path); err == nil {
						val = string(b)
					}
				}
			case "DROPDOWN":
				fmt.Fprintf(p.out, "%s:\n", label)
				for i, o := range f.ValueOptions {
					fmt.Fprintf(p.out, "  %d. %s\n", i+1, o.Label)
				}
				var ans string
				ans, err = p.line("Choose [1]: ")
				if err == nil && len(f.ValueOptions) > 0 {
					val = f.ValueOptions[0].Value
					if ans != "" {
						n, convErr := strconv.Atoi(ans)
						if convErr != nil || n < 1 || n > len(f.ValueOptions) {
							fmt.Fprintln(p.out, "Pick a number from the list.")
							continue
						}
						val = f.ValueOptions[n-1].Value
					}
				}
			default:
				dflt := f.DefaultValue
				if dflt == "" {
					dflt = knownFieldDefaults[strings.ToLower(def.Type)+"."+f.FieldName]
				}
				prompt := fmt.Sprintf("%s%s: ", label, opt)
				if dflt != "" {
					prompt = fmt.Sprintf("%s [%s]: ", label, dflt)
				}
				val, err = p.line(prompt)
				if err == nil && val == "" {
					val = dflt
				}
			}
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", label, err)
			}
			if val == "" && !f.Optional {
				fmt.Fprintf(p.out, "%s is required.\n", label)
				continue
			}
			if val != "" {
				cfg[f.FieldName] = val
			}
			break
		}
	}
	return cfg, nil
}

// apiCall sends an authenticated request to the configured server.
func apiCall(method, path string, body interface{}) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(url, "/")+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := addWorkerAuthHeaders(req); err != nil {
		return 0, nil, err
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, data, nil
}

func apiError(what string, status int, data []byte) error {
	msg := strings.TrimSpace(string(data))
	var parsed struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &parsed) == nil && parsed.Message != "" {
		msg = parsed.Message
	}
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return fmt.Errorf("%s: HTTP %d %s", what, status, msg)
}

func uiRoot() string { return strings.TrimSuffix(strings.TrimRight(url, "/"), "/api") }

func addIntegrationURL(itype string) string {
	search := itype
	if len(search) > 3 {
		search = search[:3]
	}
	q := neturl.Values{"search": {search}, "view": {"connections-and-resources"}, "type": {itype}}
	return uiRoot() + "/integrations/addIntegration?" + q.Encode()
}

func forbiddenIntegrationHelp(itype string) error {
	return fmt.Errorf("this profile's application may not create integrations (HTTP 403).\n"+
		"Ask an admin to allow it, or add the integration in the browser while signed in:\n  %s",
		addIntegrationURL(itype))
}

func providerPath(name string) string {
	return "/integrations/provider/" + neturl.PathEscape(name)
}

func fetchIntegrationDefs() ([]integrationDef, error) {
	status, data, err := apiCall(http.MethodGet, "/integrations/def", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError("listing integration types", status, data)
	}
	var defs []integrationDef
	return defs, json.Unmarshal(data, &defs)
}

func findIntegrationDef(defs []integrationDef, itype string) (integrationDef, error) {
	var types []string
	for _, d := range defs {
		if strings.EqualFold(d.Type, itype) {
			return d, nil
		}
		types = append(types, d.Type)
	}
	sort.Strings(types)
	return integrationDef{}, fmt.Errorf("unknown integration type %q. Types on this server: %s", itype, strings.Join(types, ", "))
}

func availableModels(name string) ([]string, error) {
	status, data, err := apiCall(http.MethodGet, providerPath(name)+"/integration/all", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError("listing the provider's models", status, data)
	}
	var models []string
	if err := json.Unmarshal(data, &models); err != nil {
		return nil, err
	}
	sort.Strings(models)
	return models, nil
}

// parseModelChoice turns "1,3", "all" or "" (= all) into model ids.
func parseModelChoice(ans string, available []string) ([]string, error) {
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans == "" || ans == "all" {
		return available, nil
	}
	if ans == "none" {
		return nil, nil
	}
	var out []string
	for _, part := range strings.Split(ans, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 || n > len(available) {
			return nil, fmt.Errorf("%q is not a number from the list", strings.TrimSpace(part))
		}
		out = append(out, available[n-1])
	}
	return out, nil
}

// addModels registers models under an integration. When the provider's list
// is known, ids it doesn't offer are refused with suggestions.
func addModels(out io.Writer, name string, models, available []string) ([]string, error) {
	offered := map[string]bool{}
	for _, m := range available {
		offered[m] = true
	}
	var added []string
	for _, m := range models {
		if len(available) > 0 && !offered[m] {
			var similar []string
			for _, a := range available {
				if strings.HasPrefix(a, strings.SplitN(m, "-", 2)[0]) {
					similar = append(similar, a)
				}
			}
			return added, fmt.Errorf("model %q is not offered by this key. Available: %s", m, strings.Join(similar, ", "))
		}
		status, data, err := apiCall(http.MethodPost, providerPath(name)+"/integration/"+neturl.PathEscape(m),
			map[string]interface{}{"enabled": true, "description": m})
		if err != nil {
			return added, err
		}
		if status == http.StatusForbidden {
			return added, fmt.Errorf("adding model %s: HTTP 403 — this application may not add models to %s", m, name)
		}
		if status >= 300 {
			return added, apiError("adding model "+m, status, data)
		}
		fmt.Fprintf(out, "✓ Added model %s\n", m)
		added = append(added, m)
	}
	return added, nil
}

var (
	integrationCategory    string
	integrationName        string
	integrationDescription string
	integrationModels      []string
	integrationSet         []string
	integrationAdvanced    bool
	integrationShareWith   string
	integrationAvailable   bool
)

var integrationCmd = &cobra.Command{
	Use:     "integration",
	Short:   "Orkes: manage AI / vector DB integrations and their models",
	GroupID: "conductor",
}

var integrationListCmd = &cobra.Command{
	Use:   "list",
	Short: "List integrations this profile can see",
	Example: `  conductor integration list
  conductor integration list --category AI_MODEL --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true // errors here explain what to do; usage would bury them
		status, data, err := apiCall(http.MethodGet, "/integrations/provider", nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiError("listing integrations", status, data)
		}
		var all []integrationProvider
		if err := json.Unmarshal(data, &all); err != nil {
			return err
		}
		var list []integrationProvider
		for _, p := range all {
			if integrationCategory == "" || strings.EqualFold(p.Category, integrationCategory) {
				list = append(list, p)
			}
		}
		if j, _ := cmd.Flags().GetBool("json"); j {
			b, _ := json.MarshalIndent(list, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		if len(list) == 0 {
			fmt.Println("No integrations visible to this profile. (Only integrations shared with this application are listed.)")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "NAME\tTYPE\tCATEGORY\tENABLED")
		for _, p := range list {
			fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", p.Name, p.Type, p.Category, p.Enabled)
		}
		return w.Flush()
	},
}

var integrationModelsCmd = &cobra.Command{
	Use:   "models <integration>",
	Short: "List the models registered under an integration (--available: what its key offers)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true // errors here explain what to do; usage would bury them
		if integrationAvailable {
			models, err := availableModels(args[0])
			if err != nil {
				return err
			}
			for _, m := range models {
				fmt.Println(m)
			}
			return nil
		}
		status, data, err := apiCall(http.MethodGet, providerPath(args[0])+"/integration", nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiError("listing models of "+args[0], status, data)
		}
		var models []integrationModel
		if err := json.Unmarshal(data, &models); err != nil {
			return err
		}
		if j, _ := cmd.Flags().GetBool("json"); j {
			b, _ := json.MarshalIndent(models, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "MODEL\tENABLED")
		for _, m := range models {
			fmt.Fprintf(w, "%s\t%v\n", m.Api, m.Enabled)
		}
		return w.Flush()
	},
}

var integrationAddModelCmd = &cobra.Command{
	Use:     "add-model <integration>",
	Short:   "Add models to an existing integration",
	Example: `  conductor integration add-model anthropic --model claude-sonnet-4-6`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true // errors here explain what to do; usage would bury them
		if len(integrationModels) == 0 {
			return errors.New("pass --model <id> (repeatable); see `conductor integration models " + args[0] + " --available`")
		}
		available, err := availableModels(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Note: could not list the provider's models (%v); adding without checking.\n", err)
			available = nil
		}
		_, err = addModels(os.Stdout, args[0], integrationModels, available)
		return err
	},
}

var integrationAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Create an integration; asks for the API key with a hidden prompt",
	Long: `Create an Orkes integration (an LLM provider, vector DB, …) and register its
models, as the profile's application.

Run it in your own terminal: secret fields (API keys, service-account files)
are read only from a hidden prompt or a local file — never from flags,
environment variables or the agent's chat. Non-secret fields can be preset
with --set field=value.

After creating it, the CLI asks the provider (through the server, with the key
you entered) which models the key can use. That also checks the key. Models
named with --model must be among them; without --model you pick from the list.`,
	Example: `  # Anthropic: asks for the key, then lets you pick models
  conductor integration add --type anthropic

  # Name it and add one model
  conductor integration add --type anthropic --name anthropic-prod --model claude-sonnet-4-6

  # Bedrock with an IAM role (role ARN preset, external ID asked hidden)
  conductor integration add --type aws_bedrock_anthropic --set connectionType=EXTERNAL_ROLE \
    --set region=us-east-1 --set roleArn=arn:aws:iam::123:role/conductor`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true // errors here explain what to do; usage would bury them
		itype, _ := cmd.Flags().GetString("type")
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("run this in your own terminal: it asks for the API key with a hidden prompt")
		}
		return runIntegrationAdd(terminalPrompter(), itype)
	},
}

func runIntegrationAdd(p *prompter, itype string) error {
	defs, err := fetchIntegrationDefs()
	if err != nil {
		return err
	}
	def, err := findIntegrationDef(defs, itype)
	if err != nil {
		return err
	}
	name := integrationName
	if name == "" {
		name = strings.ToLower(def.Type)
	}

	status, data, err := apiCall(http.MethodGet, providerPath(name), nil)
	if err != nil {
		return err
	}
	switch {
	case status == http.StatusOK:
		return fmt.Errorf("integration %q already exists. Add models with:\n  conductor integration add-model %s --model <id>\nor pick another --name", name, name)
	case status == http.StatusForbidden:
		// May exist but not be shared with this application; creating would collide.
		return fmt.Errorf("integration %q may already exist but isn't shared with this application; pick another --name", name)
	case status != http.StatusNotFound && status >= 300:
		return apiError("checking "+name, status, data)
	}

	preset := map[string]string{}
	for _, kv := range integrationSet {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("--set expects field=value, got %q", kv)
		}
		preset[k] = v
	}

	fmt.Fprintf(p.out, "Creating %s integration %q on %s\n", def.Name, name, uiRoot())
	cfg, err := collectIntegrationConfig(def, preset, integrationAdvanced, p)
	if err != nil {
		return err
	}

	description := integrationDescription
	if description == "" {
		description = def.Name + " (added with conductor integration add)"
	}
	status, data, err = apiCall(http.MethodPost, providerPath(name), map[string]interface{}{
		"type":          def.Type,
		"category":      def.Category,
		"enabled":       true,
		"description":   description,
		"configuration": cfg,
	})
	if err != nil {
		return err
	}
	if status == http.StatusForbidden {
		return forbiddenIntegrationHelp(def.Type)
	}
	if status >= 300 {
		return apiError("creating "+name, status, data)
	}
	fmt.Fprintf(p.out, "✓ Created integration %s (%s)\n", name, def.Type)

	available, listErr := availableModels(name)
	if listErr != nil {
		fmt.Fprintf(p.out, "Note: couldn't list models with this key (%v).\n", listErr)
		fmt.Fprintln(p.out, "      If the key is wrong, fix it in the UI; models are added without checking.")
	} else if len(available) > 0 {
		fmt.Fprintf(p.out, "✓ Key works: the provider offers %d models.\n", len(available))
	}

	models := integrationModels
	if len(models) == 0 && len(available) > 0 {
		for i, m := range available {
			fmt.Fprintf(p.out, "  %d. %s\n", i+1, m)
		}
		for {
			ans, err := p.line("Models to add (numbers like 1,3 · all · none) [all]: ")
			if err != nil {
				return err
			}
			if models, err = parseModelChoice(ans, available); err == nil {
				break
			}
			fmt.Fprintln(p.out, err)
		}
	}
	added, err := addModels(p.out, name, models, available)
	if err != nil {
		return err
	}

	if integrationShareWith != "" {
		status, data, err := apiCall(http.MethodPost, "/auth/authorization", map[string]interface{}{
			"subject": map[string]string{"type": "USER", "id": integrationShareWith},
			"target":  map[string]string{"type": "INTEGRATION_PROVIDER", "id": name},
			"access":  []string{"READ", "UPDATE", "DELETE", "EXECUTE"},
		})
		if err != nil {
			return err
		}
		if status >= 300 {
			fmt.Fprintf(p.out, "Note: %v\n", apiError("sharing with "+integrationShareWith, status, data))
		} else {
			fmt.Fprintf(p.out, "✓ Shared with %s\n", integrationShareWith)
		}
	}

	fmt.Fprintf(p.out, "\nUse it in an LLM task: \"llmProvider\": %q", name)
	if len(added) > 0 {
		fmt.Fprintf(p.out, ", \"model\": %q", added[0])
	}
	fmt.Fprintln(p.out)
	return nil
}

func init() {
	integrationListCmd.Flags().StringVar(&integrationCategory, "category", "", "only this category, e.g. AI_MODEL, VECTOR_DB")
	integrationListCmd.Flags().Bool("json", false, "print JSON")

	integrationModelsCmd.Flags().BoolVar(&integrationAvailable, "available", false, "list the models the provider's key offers instead")
	integrationModelsCmd.Flags().Bool("json", false, "print JSON")

	integrationAddModelCmd.Flags().StringArrayVar(&integrationModels, "model", nil, "model id to add (repeatable)")

	integrationAddCmd.Flags().String("type", "", "integration type, e.g. anthropic, openai, azure_openai, aws_bedrock_anthropic")
	integrationAddCmd.MarkFlagRequired("type")
	integrationAddCmd.Flags().StringVar(&integrationName, "name", "", "integration name (default: the type); this is the llmProvider value")
	integrationAddCmd.Flags().StringVar(&integrationDescription, "description", "", "description")
	integrationAddCmd.Flags().StringArrayVar(&integrationModels, "model", nil, "model id to add (repeatable); default: choose from the provider's list")
	integrationAddCmd.Flags().StringArrayVar(&integrationSet, "set", nil, "non-secret field value, field=value (repeatable)")
	integrationAddCmd.Flags().BoolVar(&integrationAdvanced, "advanced", false, "also ask for optional fields")
	integrationAddCmd.Flags().StringVar(&integrationShareWith, "share-with", "", "user id (email) to share the integration with")

	integrationCmd.AddCommand(integrationListCmd, integrationAddCmd, integrationAddModelCmd, integrationModelsCmd)
	rootCmd.AddCommand(integrationCmd)
}

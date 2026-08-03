package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestValidatePolicyRejectsDefaultAllow(t *testing.T) {
	p := Policy{Version: 1, Tools: ToolsPolicy{Default: "allow"}}
	if err := validatePolicy(p); err == nil {
		t.Fatal("expected default-allow policy to be rejected")
	}
}

func TestLoadPolicyRejectsUnknownFieldsAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\ntools:\n  default: deny\nunknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
	validPath := filepath.Join(dir, "valid.yaml")
	if err := os.WriteFile(validPath, []byte("version: 1\ntools:\n  default: deny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(validPath, linkPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	t.Setenv("POLICY_PATH", linkPath)
	if err := loadPolicy(); err == nil {
		t.Fatal("expected policy symlink to be rejected")
	}
}

func TestPathAllowlistRequiresAPathAndChecksAliases(t *testing.T) {
	entry := ToolEntry{PathsAllowlist: []string{"/vault/**"}}
	if ok, _ := checkPathConstraints(map[string]string{}, entry); ok {
		t.Fatal("missing path must fail closed")
	}
	if ok, _ := checkPathConstraints(map[string]string{"filename": "/etc/shadow"}, entry); ok {
		t.Fatal("alternate path key escaped allowlist")
	}
	if ok, _ := checkPathConstraints(map[string]string{"path": "relative/file.txt"}, entry); ok {
		t.Fatal("relative path escaped absolute-path requirement")
	}
}

func TestSanitizeAuditParamsRedactsSecretKeys(t *testing.T) {
	got := sanitizeAuditParams(map[string]string{
		"custom_token": "sensitive-value",
		"path":         "/vault/report.txt",
	}, Policy{})
	secret, _ := got["custom_token"].(string)
	if strings.Contains(secret, "sensitive-value") || !strings.Contains(secret, "[redacted") {
		t.Fatalf("secret was not redacted: %q", secret)
	}
	if got["path"] != "/vault/report.txt" {
		t.Fatalf("non-sensitive path unexpectedly changed: %q", got["path"])
	}
}

func TestSanitizeAuditParamsNeverStoresSecrets(t *testing.T) {
	pol := Policy{}
	pol.Defaults.Logging.StoreRawPrompts = true
	pol.Defaults.Logging.StoreRawResponses = true
	got := sanitizeAuditParams(map[string]string{
		"password":    "do-not-record",
		"private_key": "do-not-record-either",
	}, pol)
	for key, value := range got {
		valueString, _ := value.(string)
		if strings.Contains(valueString, "do-not-record") || !strings.Contains(valueString, "[redacted") {
			t.Fatalf("secret %q was not unconditionally redacted: %q", key, valueString)
		}
	}
}

func TestSanitizeAuditParamsRecursivelyRedactsNestedSecrets(t *testing.T) {
	got := sanitizeAuditParams(map[string]any{
		"outer": map[string]any{
			"token": "never-record-this",
			"safe":  "visible",
		},
	}, Policy{})
	outer, ok := got["outer"].(map[string]any)
	if !ok {
		t.Fatalf("nested object was not retained: %#v", got)
	}
	secret, _ := outer["token"].(string)
	if strings.Contains(secret, "never-record-this") || !strings.Contains(secret, "[redacted") {
		t.Fatalf("nested secret was not redacted: %#v", outer)
	}
	if outer["safe"] != "visible" {
		t.Fatalf("safe nested value was unexpectedly changed: %#v", outer)
	}
}

func TestSanitizeAuditParamsCanonicalizesCredentialAliasesWithoutFingerprints(t *testing.T) {
	pol := Policy{}
	pol.Defaults.Logging.StoreRawPrompts = true
	pol.Defaults.Logging.StoreRawResponses = true
	got := sanitizeAuditParams(map[string]any{
		"privateKey": "dictionary-password",
		"ssh-key":    "ssh-secret",
		"nested": []any{map[string]any{
			"signing_key": "signing-secret",
			"apiKey":      "api-secret",
		}},
	}, pol)
	assertCredential := func(label string, value any) {
		t.Helper()
		text, ok := value.(string)
		if !ok || text != "[redacted credential]" || strings.Contains(text, "sha256") {
			t.Fatalf("credential alias %s retained verifier material: %#v", label, value)
		}
	}
	assertCredential("privateKey", got["privateKey"])
	assertCredential("ssh-key", got["ssh-key"])
	nested, ok := got["nested"].([]any)
	if !ok || len(nested) != 1 {
		t.Fatalf("nested credential structure changed unexpectedly: %#v", got["nested"])
	}
	nestedMap, ok := nested[0].(map[string]any)
	if !ok {
		t.Fatalf("nested credential object changed unexpectedly: %#v", nested[0])
	}
	assertCredential("signing_key", nestedMap["signing_key"])
	assertCredential("apiKey", nestedMap["apiKey"])

	pol.Tools.Allow = []ToolEntry{{
		Name:     "custom",
		ArgRules: []ToolArgRule{{Name: "opaque", Type: "string", Redact: true}},
	}}
	explicit := sanitizeToolAuditParams(map[string]any{"opaque": "low-entropy"}, pol, "custom")
	assertCredential("explicit redact rule", explicit["opaque"])
}

func TestArgsBlocklistInspectsRawAndNestedStringsWithoutHTMLEscaping(t *testing.T) {
	entry := ToolEntry{ArgsBlacklist: []string{"&&", "<script>", ">"}}
	cases := []struct {
		name  string
		value any
	}{
		{name: "ampersands", value: "printf safe && id"},
		{name: "html opener", value: "<script>run()</script>"},
		{name: "redirect", value: "output > /tmp/result"},
		{name: "nested array", value: map[string]any{"items": []any{"safe", "nested && command"}}},
		{name: "nested key", value: map[string]any{"<script>": "value"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := ToolCallRequest{TypedParams: map[string]any{"note": tc.value}}
			if ok, reason := validateArgs(req, entry); ok || !strings.Contains(reason, "blocked pattern") {
				t.Fatalf("blocklisted raw/nested value was accepted: ok=%t reason=%q", ok, reason)
			}
		})
	}
	clean := ToolCallRequest{TypedParams: map[string]any{"note": map[string]any{"items": []any{"safe", "still safe"}}}}
	if ok, reason := validateArgs(clean, entry); !ok {
		t.Fatalf("clean nested value was rejected: %s", reason)
	}
}

func TestSanitizeAuditParamsUsesIndependentPromptAndResponseControls(t *testing.T) {
	pol := Policy{}
	pol.Defaults.Logging.StoreRawResponses = true
	got := sanitizeAuditParams(map[string]any{
		"prompt":   "redact-me",
		"response": "retain-me",
	}, pol)
	if got["response"] != "retain-me" {
		t.Fatalf("raw response control was coupled to prompt control: %#v", got)
	}
	if prompt, _ := got["prompt"].(string); !strings.Contains(prompt, "[redacted") {
		t.Fatalf("prompt was retained while raw prompts were disabled: %#v", got)
	}
}

func TestTypedArgumentsAndUndeclaredDangerousFields(t *testing.T) {
	entry := ToolEntry{ArgRules: []ToolArgRule{{Name: "count", Type: "integer", Required: true}}}
	valid := ToolCallRequest{TypedParams: map[string]any{"count": json.Number("2")}}
	if ok, reason := validateArgs(valid, entry); !ok {
		t.Fatalf("valid typed argument denied: %s", reason)
	}
	wrongType := ToolCallRequest{TypedParams: map[string]any{"count": "2"}}
	if ok, _ := validateArgs(wrongType, entry); ok {
		t.Fatal("string bypassed integer argument rule")
	}
	legacy := ToolEntry{}
	if ok, _ := validateArgs(ToolCallRequest{TypedParams: map[string]any{"command": "id"}}, legacy); ok {
		t.Fatal("undeclared command argument was allowed")
	}
	if ok, _ := validateArgs(ToolCallRequest{TypedParams: map[string]any{"shell-command": "id"}}, legacy); ok {
		t.Fatal("separator-obfuscated command argument was allowed")
	}
	if ok, _ := validateArgs(ToolCallRequest{TypedParams: map[string]any{"privateKey": "secret"}}, legacy); ok {
		t.Fatal("undeclared credential alias was allowed")
	}
	noArguments := ToolEntry{ArgRules: []ToolArgRule{}}
	if ok, _ := validateArgs(ToolCallRequest{TypedParams: map[string]any{"label": "unexpected"}}, noArguments); ok {
		t.Fatal("explicitly empty typed contract accepted an argument")
	}
}

func TestTypedPathChecksCannotBypassNormalizedParameters(t *testing.T) {
	entry := ToolEntry{
		ArgRules:       []ToolArgRule{{Name: "path", Type: "string", Required: true}},
		PathsAllowlist: []string{"/vault/**"},
	}
	req := ToolCallRequest{Tool: "filesystem.read", TypedParams: map[string]any{"path": "/etc/shadow"}}
	if ok, _ := checkPathConstraints(normalizeParams(effectiveTypedParams(req)), entry); ok {
		t.Fatal("typed path escaped the path allowlist")
	}
	entry = ToolEntry{PathsDenylist: []string{"/etc/**"}}
	if ok, _ := checkPathConstraints(map[string]string{"path": ""}, entry); ok {
		t.Fatal("empty path bypassed a deny-only path policy")
	}
	if ok, _ := checkPathConstraints(map[string]string{}, entry); ok {
		t.Fatal("missing path bypassed a deny-only path policy")
	}
}

func TestValidateBindAddressRequiresExplicitRemoteOptIn(t *testing.T) {
	t.Setenv("ALLOW_REMOTE_BIND", "")
	if err := validateBindAddress("127.0.0.1:8475"); err != nil {
		t.Fatalf("loopback bind rejected: %v", err)
	}
	if err := validateBindAddress("0.0.0.0:8475"); err == nil {
		t.Fatal("remote bind accepted without opt-in")
	}
	t.Setenv("ALLOW_REMOTE_BIND", "true")
	if err := validateBindAddress("0.0.0.0:8475"); err != nil {
		t.Fatalf("explicit remote bind rejected: %v", err)
	}
}

func TestWriteAuditProducesDurableJSONL(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	old := auditFile
	auditFile = f
	t.Cleanup(func() {
		auditFile = old
		_ = f.Close()
	})
	if err := writeAudit(AuditEntry{Tool: "test", Allowed: false, Reason: "denied"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil || entry.Tool != "test" {
		t.Fatalf("invalid audit entry: %v %q", err, data)
	}
}

func TestInitAuditLogRejectsBroadPermissionsAndHardlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUDIT_LOG_PATH", path)
	if err := initAuditLog(); err == nil {
		t.Fatal("audit file with group/other permissions was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit-link.jsonl")
	if err := os.Link(path, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := initAuditLog(); err == nil {
		t.Fatal("hard-linked audit file was accepted")
	}
}

func TestWriteAuditRejectsPathReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv("AUDIT_LOG_PATH", path)
	oldFile, oldPath := auditFile, auditPath
	if err := initAuditLog(); err != nil {
		t.Fatal(err)
	}
	opened := auditFile
	t.Cleanup(func() {
		_ = opened.Close()
		auditFile, auditPath = oldFile, oldPath
	})
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAudit(AuditEntry{Event: "replacement-test"}); err == nil {
		t.Fatal("audit append continued after path replacement")
	}
}

func TestWriteAuditEnforcesRuntimePermissionsAndSizeCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv("AUDIT_LOG_PATH", path)
	oldFile, oldPath := auditFile, auditPath
	if err := initAuditLog(); err != nil {
		t.Fatal(err)
	}
	opened := auditFile
	t.Cleanup(func() {
		_ = opened.Close()
		auditFile, auditPath = oldFile, oldPath
	})
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeAudit(AuditEntry{Event: "permission-test"}); err == nil {
		t.Fatal("audit append continued after permissions widened")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := opened.Truncate(maxAuditSize); err != nil {
		t.Fatal(err)
	}
	if err := writeAudit(AuditEntry{Event: "size-test"}); err == nil {
		t.Fatal("audit append exceeded the runtime size cap")
	}
}

func TestReloadAndEvaluationAuditDigestsRemainTransactionallyOrdered(t *testing.T) {
	setupTestPolicy()
	oldPolicy, oldDigest := getPolicySnapshot()
	if oldDigest == "" {
		t.Fatal("initial policy digest was not set")
	}
	setupTestAudit(t)
	auditName := auditFile.Name()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	newPolicyYAML := "version: 1\ndefaults:\n  network:\n    runtime_egress: deny\n  logging:\n    store_raw_prompts: false\n    store_raw_responses: false\ntools:\n  default: deny\n  allow: []\n  deny: []\n  rate_limit:\n    requests_per_minute: 120\n    burst_size: 20\n"
	if err := os.WriteFile(policyPath, []byte(newPolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_PATH", policyPath)
	newPolicy, err := readPolicyFile()
	if err != nil {
		t.Fatal(err)
	}
	newDigest, err := computePolicyDigest(newPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if newDigest == oldDigest || oldPolicy.Tools.Default != "deny" {
		t.Fatal("test policies did not produce distinct valid digests")
	}

	start := make(chan struct{})
	statuses := make(chan int, 25)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			request := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(`{"tool":"unknown.tool"}`))
			response := httptest.NewRecorder()
			handleEvaluate(response, request)
			statuses <- response.Code
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		request := httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
		response := httptest.NewRecorder()
		handleReload(response, request)
		statuses <- response.Code
	}()
	close(start)
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("concurrent request returned %d", status)
		}
	}

	data, err := os.ReadFile(auditName)
	if err != nil {
		t.Fatal(err)
	}
	activeDigest := oldDigest
	reloads := 0
	evaluations := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode audit entry: %v", err)
		}
		switch entry.Event {
		case "reload":
			reloads++
			if entry.OldPolicyDigest != activeDigest || entry.NewPolicyDigest != newDigest {
				t.Fatalf("invalid reload transition: %#v", entry)
			}
			activeDigest = entry.NewPolicyDigest
		case "evaluate":
			evaluations++
			if entry.PolicyDigest != activeDigest {
				t.Fatalf("evaluation digest %q does not match audit-ordered active digest %q", entry.PolicyDigest, activeDigest)
			}
		}
	}
	if reloads != 1 || evaluations != 24 {
		t.Fatalf("got %d reload and %d evaluation records", reloads, evaluations)
	}
}

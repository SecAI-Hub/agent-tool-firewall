package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func trustedCredentialTestDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".agent-tool-firewall-credentials-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestScopedCredentialsEnforceExactRoles(t *testing.T) {
	evaluator := strings.Repeat("e", 32)
	observer := strings.Repeat("o", 32)
	admin := strings.Repeat("a", 32)
	credentials, err := newCredentialSet([]credentialPrincipal{
		{identity: "runtime-a", tokenDigest: sha256.Sum256([]byte(evaluator)), roles: roleMap(roleEvaluator)},
		{identity: "monitor", tokenDigest: sha256.Sum256([]byte(observer)), roles: roleMap(roleObserver)},
		{identity: "operator", tokenDigest: sha256.Sum256([]byte(admin)), roles: roleMap(roleAdministrator)},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/evaluate", requireRole(roleEvaluator, func(w http.ResponseWriter, r *http.Request) {
		if authenticatedIdentity(r) != "runtime-a" {
			t.Fatal("authenticated identity was not bound to the request")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/observe", requireRole(roleObserver, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	mux.HandleFunc("/admin", requireRole(roleAdministrator, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	handler := authenticatedHandler(mux, credentials)

	for _, test := range []struct {
		path, token string
		want        int
	}{
		{"/evaluate", evaluator, http.StatusNoContent},
		{"/evaluate", observer, http.StatusForbidden},
		{"/evaluate", admin, http.StatusForbidden},
		{"/observe", observer, http.StatusNoContent},
		{"/admin", admin, http.StatusNoContent},
		{"/admin", evaluator, http.StatusForbidden},
		{"/evaluate", "wrong", http.StatusUnauthorized},
		{"/evaluate", strings.Repeat("z", maxTokenSize+1), http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(http.MethodGet, test.path, nil)
		req.Header.Set("Authorization", "Bearer "+test.token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != test.want {
			t.Fatalf("%s returned %d, want %d", test.path, response.Code, test.want)
		}
	}
}

func TestCredentialConfigurationLoadsIdentityAndRejectsUnsafeRoleSets(t *testing.T) {
	if _, err := loadCredentialSetFile("relative-credentials.yaml"); err == nil {
		t.Fatal("relative credential configuration path was accepted")
	}
	dir := trustedCredentialTestDir(t)
	paths := make([]string, 3)
	for i, value := range []string{strings.Repeat("e", 32), strings.Repeat("o", 32), strings.Repeat("a", 32)} {
		paths[i] = filepath.Join(dir, fmt.Sprintf("token-%d", i))
		if err := os.WriteFile(paths[i], []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(dir, "credentials.yaml")
	body := fmt.Sprintf("version: 1\ncredentials:\n  - identity: runtime-a\n    token_path: %s\n    roles: [evaluator]\n  - identity: monitor\n    token_path: %s\n    roles: [observer]\n  - identity: operator\n    token_path: %s\n    roles: [administrator]\n", paths[0], paths[1], paths[2])
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials, err := loadCredentialSetFile(config)
	if err != nil || len(credentials.principals) != 3 {
		t.Fatalf("valid credential configuration rejected: %v", err)
	}

	principals := []credentialPrincipal{
		{identity: "combined-admin", tokenDigest: sha256.Sum256([]byte(strings.Repeat("x", 32))), roles: roleMap(roleAdministrator, roleObserver)},
		{identity: "runtime", tokenDigest: sha256.Sum256([]byte(strings.Repeat("y", 32))), roles: roleMap(roleEvaluator)},
	}
	if _, err := newCredentialSet(principals); err == nil {
		t.Fatal("administrator combined with another role was accepted")
	}
	principals = []credentialPrincipal{
		{identity: "runtime", tokenDigest: sha256.Sum256([]byte(strings.Repeat("x", 32))), roles: roleMap(roleEvaluator)},
		{identity: "operator", tokenDigest: sha256.Sum256([]byte(strings.Repeat("x", 32))), roles: roleMap(roleAdministrator)},
	}
	if _, err := newCredentialSet(principals); err == nil {
		t.Fatal("duplicate token values were accepted for different identities")
	}
}

func TestCredentialSourcesRequireTrustedOwnersAndParentChain(t *testing.T) {
	dir := trustedCredentialTestDir(t)
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("t", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTokenFile(token, "test token"); err != nil {
		t.Fatalf("trusted token rejected: %v", err)
	}

	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTokenFile(token, "test token"); err == nil {
		t.Fatal("token beneath a group-writable parent was accepted")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	expectedUID := os.Geteuid() + 1
	if os.Geteuid() == 0 {
		expectedUID = 0
		if err := os.Chown(token, 65534, -1); err != nil {
			t.Skipf("cannot create mismatched-owner fixture: %v", err)
		}
	}
	identities, err := inspectTrustedCredentialPath(token, 0o077, expectedUID)
	if err == nil || identities != nil {
		t.Fatal("credential path owned by neither root nor the expected effective uid was accepted")
	}

	link := filepath.Join(dir, "token-link")
	if err := os.Symlink(token, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := loadTokenFile(link, "test token"); err == nil {
		t.Fatal("credential token symlink was accepted")
	}
}

func TestProductionMuxEnforcesFullRoleMatrix(t *testing.T) {
	setupTestPolicy()
	setupTestAudit(t)
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	policyYAML := "version: 1\ndefaults:\n  network:\n    runtime_egress: deny\n  logging:\n    store_raw_prompts: false\n    store_raw_responses: false\ntools:\n  default: deny\n  allow: []\n  deny: []\n  rate_limit:\n    requests_per_minute: 120\n    burst_size: 20\n"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_PATH", policyPath)

	tokens := map[gatewayRole]string{
		roleEvaluator:     strings.Repeat("e", 32),
		roleObserver:      strings.Repeat("o", 32),
		roleAdministrator: strings.Repeat("a", 32),
	}
	credentials, err := newCredentialSet([]credentialPrincipal{
		{identity: "runtime-a", tokenDigest: sha256.Sum256([]byte(tokens[roleEvaluator])), roles: roleMap(roleEvaluator)},
		{identity: "monitor", tokenDigest: sha256.Sum256([]byte(tokens[roleObserver])), roles: roleMap(roleObserver)},
		{identity: "operator", tokenDigest: sha256.Sum256([]byte(tokens[roleAdministrator])), roles: roleMap(roleAdministrator)},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := authenticatedHandler(newToolFirewallMux(), credentials)

	endpoints := []struct {
		name, method, path, body string
		role                     gatewayRole
		allowedStatus            int
	}{
		{"evaluate", http.MethodPost, "/v1/evaluate", `{"tool":"unknown.tool"}`, roleEvaluator, http.StatusOK},
		{"stats", http.MethodGet, "/v1/stats", "", roleObserver, http.StatusOK},
		{"reload", http.MethodPost, "/v1/reload", "", roleAdministrator, http.StatusOK},
	}
	roles := []gatewayRole{roleEvaluator, roleObserver, roleAdministrator}
	for _, endpoint := range endpoints {
		for _, role := range roles {
			t.Run(endpoint.name+"/"+string(role), func(t *testing.T) {
				req := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.body))
				req.Header.Set("Authorization", "Bearer "+tokens[role])
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				want := http.StatusForbidden
				if role == endpoint.role {
					want = endpoint.allowedStatus
				}
				if response.Code != want {
					t.Fatalf("got %d, want %d: %s", response.Code, want, response.Body.String())
				}
			})
		}
		t.Run(endpoint.name+"/unauthenticated", func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.body)))
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", response.Code)
			}
		})
	}
}

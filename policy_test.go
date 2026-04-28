package main

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// setupMaliciousInputPolicy creates a policy with filesystem.read (restricted
// paths, blocklist, short arg limit) and web.search (blocklist only).
func setupMaliciousInputPolicy() {
	policyMu.Lock()
	policy = Policy{
		Version: 1,
		Tools: ToolsPolicy{
			Default: "deny",
			Allow: []ToolEntry{
				{
					Name:           "filesystem.read",
					PathsAllowlist: []string{"/vault/user_docs/**"},
					PathsDenylist:  []string{"/etc/shadow", "/etc/passwd"},
					ArgsBlacklist:  []string{"password", "../", "rm -rf"},
					MaxArgLength:   256,
				},
				{
					Name:          "web.search",
					ArgsBlacklist: []string{"secret", "api_key", "token"},
					MaxArgLength:  1024,
				},
			},
			Deny: []ToolEntry{
				{Name: "shell.exec"},
			},
			RateLimit: RateConfig{
				RequestsPerMinute: 10000, // high limit so rate limiter doesn't interfere
				BurstSize:         1000,
			},
		},
	}
	policyMu.Unlock()
}

// ---------------------------------------------------------------------------
// Path traversal attacks
// ---------------------------------------------------------------------------

func TestPathTraversal_RelativeEscape(t *testing.T) {
	setupMaliciousInputPolicy()

	cases := []struct {
		name string
		path string
	}{
		{"basic dot-dot", "/vault/user_docs/../../etc/shadow"},
		{"deep traversal", "/vault/user_docs/../../../../../../../etc/shadow"},
		{"mid-path traversal", "/vault/user_docs/subdir/../../etc/passwd"},
		{"double dot only", "../../etc/shadow"},
		{"traversal to root", "/vault/user_docs/../.."},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evaluateTool(ToolCallRequest{
				Tool:   "filesystem.read",
				Params: map[string]string{"path": tc.path},
			})
			if resp.Allowed {
				t.Errorf("path traversal %q should be denied", tc.path)
			}
		})
	}
}

func TestPathTraversal_NullByteInjection(t *testing.T) {
	setupMaliciousInputPolicy()

	cases := []struct {
		name string
		path string
	}{
		{"null at end", "/vault/user_docs/file.txt\x00"},
		{"null mid-path", "/vault/user_docs/\x00../../etc/shadow"},
		{"null before extension", "/vault/user_docs/file\x00.jpg"},
		{"null between dirs", "/vault/user_docs\x00/../../etc/passwd"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evaluateTool(ToolCallRequest{
				Tool:   "filesystem.read",
				Params: map[string]string{"path": tc.path},
			})
			if resp.Allowed {
				t.Errorf("null byte path %q should be denied", tc.path)
			}
			if resp.Allowed || !strings.Contains(resp.Reason, "null byte") {
				if resp.Allowed {
					t.Errorf("expected denial with null byte reason")
				}
			}
		})
	}
}

func TestPathTraversal_URLEncodedPaths(t *testing.T) {
	setupMaliciousInputPolicy()

	cases := []struct {
		name      string
		path      string
		wantAllow bool
	}{
		{"percent-encoded dot-dot", "/vault/user_docs/%2e%2e/%2e%2e/etc/shadow", false},
		{"mixed real-dotdot with encoded slash", "/vault/user_docs/..%2f..%2fetc/shadow", false},
		{"double encoding", "/vault/user_docs/%252e%252e/etc/shadow", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evaluateTool(ToolCallRequest{
				Tool:   "filesystem.read",
				Params: map[string]string{"path": tc.path},
			})
			if resp.Allowed != tc.wantAllow {
				t.Errorf("path %q: allowed=%v, want=%v (reason=%s)",
					tc.path, resp.Allowed, tc.wantAllow, resp.Reason)
			}
		})
	}
}

func TestPathTraversal_SymlinkTricks(t *testing.T) {
	setupMaliciousInputPolicy()

	// Symlink-style paths: these resolve to locations outside the allowlist
	// after filepath.Clean + filepath.Abs canonicalization.
	cases := []struct {
		name string
		path string
	}{
		{"absolute escape via dot-dot", "/vault/user_docs/../../../../etc/shadow"},
		{"trailing slash traversal", "/vault/user_docs/../"},
		{"dot-dot with trailing component", "/vault/user_docs/../../tmp/evil"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evaluateTool(ToolCallRequest{
				Tool:   "filesystem.read",
				Params: map[string]string{"path": tc.path},
			})
			if resp.Allowed {
				t.Errorf("symlink-style traversal %q should be denied", tc.path)
			}
		})
	}
}

func TestPathTraversal_UnicodeNormalization(t *testing.T) {
	setupMaliciousInputPolicy()

	cases := []struct {
		name      string
		path      string
		wantAllow bool
	}{
		{"fullwidth dots", "/vault/user_docs/\uff0e\uff0e\uff0fetc/shadow", false},
		{"combining dot", "/vault/user_docs/.\u0323./etc/shadow", false},
		{"fullwidth slash mixed", "/vault/user_docs\uff0f\uff0e\uff0e/etc/shadow", false},
		{"replacement char path", "/vault/user_docs/\ufffd\ufffd/etc/shadow", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evaluateTool(ToolCallRequest{
				Tool:   "filesystem.read",
				Params: map[string]string{"path": tc.path},
			})
			if resp.Allowed != tc.wantAllow {
				t.Errorf("unicode path %q: allowed=%v, want=%v (reason=%s)",
					tc.path, resp.Allowed, tc.wantAllow, resp.Reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Oversized argument tests
// ---------------------------------------------------------------------------

func TestOversizedArguments(t *testing.T) {
	setupMaliciousInputPolicy()

	cases := []struct {
		name   string
		tool   string
		key    string
		length int
	}{
		{"path exceeds 256", "filesystem.read", "path", 257},
		{"path far exceeds limit", "filesystem.read", "path", 10000},
		{"query exceeds 1024", "web.search", "query", 1025},
		{"query far exceeds limit", "web.search", "query", 100000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bigVal := strings.Repeat("a", tc.length)
			resp := evaluateTool(ToolCallRequest{
				Tool:   tc.tool,
				Params: map[string]string{tc.key: bigVal},
			})
			if resp.Allowed {
				t.Errorf("argument of length %d should exceed max_arg_length", tc.length)
			}
			if !strings.Contains(resp.Reason, "exceeds max length") {
				t.Errorf("expected max length reason, got: %s", resp.Reason)
			}
		})
	}
}

func TestArgumentExactlyAtLimit(t *testing.T) {
	setupMaliciousInputPolicy()

	// Exactly at the 256-byte limit should be allowed (path still needs to match allowlist)
	exactVal := "/vault/user_docs/" + strings.Repeat("a", 256-len("/vault/user_docs/"))
	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": exactVal},
	})
	// Should NOT be denied for length — may be denied for path not matching
	// but the reason must not mention "exceeds max length"
	if !resp.Allowed && strings.Contains(resp.Reason, "exceeds max length") {
		t.Error("argument at exact limit should not be rejected for length")
	}
}

// ---------------------------------------------------------------------------
// Blocklisted pattern tests
// ---------------------------------------------------------------------------

func TestBlocklistedPatterns(t *testing.T) {
	setupMaliciousInputPolicy()

	cases := []struct {
		name  string
		tool  string
		key   string
		value string
	}{
		{"password in arg", "filesystem.read", "note", "my password is 123"},
		{"PASSWORD uppercase", "filesystem.read", "note", "my PASSWORD is 123"},
		{"PaSsWoRd mixed case", "filesystem.read", "note", "PaSsWoRd"},
		{"../ in argument", "filesystem.read", "note", "go to ../etc"},
		{"rm -rf in argument", "filesystem.read", "note", "rm -rf /"},
		{"secret in search", "web.search", "query", "find the secret"},
		{"api_key in search", "web.search", "query", "api_key=abc123"},
		{"token in search", "web.search", "query", "bearer token value"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evaluateTool(ToolCallRequest{
				Tool:   tc.tool,
				Params: map[string]string{tc.key: tc.value},
			})
			if resp.Allowed {
				t.Errorf("blocklisted pattern in %q=%q should be denied", tc.key, tc.value)
			}
			if !strings.Contains(resp.Reason, "blocked pattern") {
				t.Errorf("expected blocked pattern reason, got: %s", resp.Reason)
			}
		})
	}
}

func TestBlocklistCleanArguments(t *testing.T) {
	setupMaliciousInputPolicy()

	// These should NOT trigger the blocklist
	cases := []struct {
		name  string
		tool  string
		key   string
		value string
	}{
		{"normal search", "web.search", "query", "weather forecast"},
		{"safe search", "web.search", "query", "golang best practices"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evaluateTool(ToolCallRequest{
				Tool:   tc.tool,
				Params: map[string]string{tc.key: tc.value},
			})
			if !resp.Allowed {
				t.Errorf("clean argument %q=%q should be allowed, denied with: %s", tc.key, tc.value, resp.Reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Empty / nil policy handling
// ---------------------------------------------------------------------------

func TestEmptyPolicy_DefaultDeny(t *testing.T) {
	// An empty policy with no allow/deny entries should deny everything
	policyMu.Lock()
	policy = Policy{
		Version: 1,
		Tools: ToolsPolicy{
			Default:   "deny",
			Allow:     nil,
			Deny:      nil,
			RateLimit: RateConfig{RequestsPerMinute: 10000},
		},
	}
	policyMu.Unlock()

	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": "/vault/user_docs/file.txt"},
	})
	if resp.Allowed {
		t.Error("empty deny policy should reject all tools")
	}
	if resp.Reason != "tool not in allowlist" {
		t.Errorf("expected 'tool not in allowlist', got: %s", resp.Reason)
	}
}

func TestEmptyPolicy_EmptyAllowList(t *testing.T) {
	policyMu.Lock()
	policy = Policy{
		Version: 1,
		Tools: ToolsPolicy{
			Default:   "deny",
			Allow:     []ToolEntry{},
			Deny:      []ToolEntry{},
			RateLimit: RateConfig{RequestsPerMinute: 10000},
		},
	}
	policyMu.Unlock()

	resp := evaluateTool(ToolCallRequest{
		Tool:   "anything",
		Params: map[string]string{},
	})
	if resp.Allowed {
		t.Error("empty allowlist with default-deny should reject all tools")
	}
}

func TestEmptyPolicy_NilParams(t *testing.T) {
	setupMaliciousInputPolicy()

	// nil params map should not panic
	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: nil,
	})
	// Should be allowed since filesystem.read is in the allowlist and no path
	// to validate
	if !resp.Allowed {
		t.Errorf("nil params should be allowed for listed tool, got: %s", resp.Reason)
	}
}

func TestEmptyPolicy_EmptyToolName(t *testing.T) {
	setupMaliciousInputPolicy()

	resp := evaluateTool(ToolCallRequest{
		Tool:   "",
		Params: map[string]string{},
	})
	if resp.Allowed {
		t.Error("empty tool name should be denied")
	}
}

func TestEmptyPolicy_DefaultAllow(t *testing.T) {
	// When default is "allow", unknown tools should be permitted
	policyMu.Lock()
	policy = Policy{
		Version: 1,
		Tools: ToolsPolicy{
			Default:   "allow",
			Allow:     nil,
			Deny:      nil,
			RateLimit: RateConfig{RequestsPerMinute: 10000},
		},
	}
	policyMu.Unlock()

	resp := evaluateTool(ToolCallRequest{
		Tool:   "unknown.tool",
		Params: map[string]string{},
	})
	if !resp.Allowed {
		t.Error("default-allow policy should permit unknown tools")
	}
}

// ---------------------------------------------------------------------------
// Path validation edge cases
// ---------------------------------------------------------------------------

func TestPathValidation_DenylistTakesPriority(t *testing.T) {
	// Even if a path matches the allowlist, the denylist should win
	policyMu.Lock()
	policy = Policy{
		Version: 1,
		Tools: ToolsPolicy{
			Default: "deny",
			Allow: []ToolEntry{
				{
					Name:           "filesystem.read",
					PathsAllowlist: []string{"/etc/**"},
					PathsDenylist:  []string{"/etc/shadow"},
					MaxArgLength:   4096,
				},
			},
			RateLimit: RateConfig{RequestsPerMinute: 10000},
		},
	}
	policyMu.Unlock()

	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": "/etc/shadow"},
	})
	if resp.Allowed {
		t.Error("denylisted path should be denied even if it matches allowlist")
	}
}

func TestPathValidation_EmptyPath(t *testing.T) {
	setupMaliciousInputPolicy()

	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": ""},
	})
	// Empty path should pass path validation (checkPathConstraints returns true for empty)
	if !resp.Allowed {
		t.Errorf("empty path should be allowed, got: %s", resp.Reason)
	}
}

func TestPathValidation_AbsoluteOutsideAllowlist(t *testing.T) {
	setupMaliciousInputPolicy()

	cases := []string{
		"/tmp/evil",
		"/root/.ssh/id_rsa",
		"/proc/self/environ",
		"/dev/sda",
	}

	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			resp := evaluateTool(ToolCallRequest{
				Tool:   "filesystem.read",
				Params: map[string]string{"path": p},
			})
			if resp.Allowed {
				t.Errorf("path %q outside allowlist should be denied", p)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// cleanAndResolvePath unit tests
// ---------------------------------------------------------------------------

func TestCleanAndResolvePath(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty string", "", false},
		{"absolute clean path", "/vault/user_docs/file.txt", false},
		{"traversal path", "/vault/user_docs/../../etc/shadow", false},
		{"null byte", "/vault/user_docs/\x00file", true},
		{"null byte only", "\x00", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cleanAndResolvePath(tc.input)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestCleanAndResolvePath_Canonicalization(t *testing.T) {
	// Verify that traversal sequences are resolved
	result, err := cleanAndResolvePath("/vault/user_docs/../../etc/shadow")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(result, "..") {
		t.Errorf("resolved path should not contain '..': %s", result)
	}
	if !strings.HasSuffix(normalizeMatchPath(result), "/etc/shadow") {
		t.Errorf("expected path ending in /etc/shadow, got: %s", result)
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

type Policy struct {
	Version  int            `yaml:"version"`
	Defaults PolicyDefaults `yaml:"defaults"`
	Tools    ToolsPolicy    `yaml:"tools"`
}

type PolicyDefaults struct {
	Network struct {
		RuntimeEgress string `yaml:"runtime_egress"`
	} `yaml:"network"`
	Logging struct {
		StoreRawPrompts   bool `yaml:"store_raw_prompts"`
		StoreRawResponses bool `yaml:"store_raw_responses"`
	} `yaml:"logging"`
}

type ToolsPolicy struct {
	Default   string      `yaml:"default"`
	Allow     []ToolEntry `yaml:"allow"`
	Deny      []ToolEntry `yaml:"deny"`
	RateLimit RateConfig  `yaml:"rate_limit"`
}

type ToolEntry struct {
	Name           string        `yaml:"name"`
	PathsAllowlist []string      `yaml:"paths_allowlist"`
	PathsDenylist  []string      `yaml:"paths_denylist"`
	ArgsBlacklist  []string      `yaml:"args_blocklist"`
	ArgRules       []ToolArgRule `yaml:"args"`
	MaxArgLength   int           `yaml:"max_arg_length"`
}

// ToolArgRule defines the expected JSON type and constraints for one argument.
// When a tool declares any argument rules, the rules are a complete allowlist.
type ToolArgRule struct {
	Name      string `yaml:"name"`
	Type      string `yaml:"type"`
	Required  bool   `yaml:"required"`
	MaxLength int    `yaml:"max_length"`
	Pattern   string `yaml:"pattern"`
	Redact    bool   `yaml:"redact"`
}

type RateConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	BurstSize         int `yaml:"burst_size"`
}

// ---------------------------------------------------------------------------
// Request / response
// ---------------------------------------------------------------------------

type ToolCallRequest struct {
	Tool   string            `json:"tool"`
	Params map[string]string `json:"params"`
	// TypedParams retains the original bounded JSON values received over HTTP.
	// Params remains for source compatibility with existing in-process clients.
	TypedParams map[string]any `json:"-"`
}

type toolCallRequestWire struct {
	Tool   string         `json:"tool"`
	Params map[string]any `json:"params"`
	Args   map[string]any `json:"args,omitempty"` // legacy alias accepted for compatibility
}

type ToolCallResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   Policy
	// policyDigest is updated in the same critical section as policy. An
	// evaluation holds policyMu for the decision and its durable audit append,
	// so the digest recorded for that decision is always the exact policy used.
	policyDigest string

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	// Rate limiting: process-wide token bucket.
	rateMu     sync.Mutex
	rateTokens float64
	rateLast   time.Time
	rateRPM    int
	rateBurst  int

	// Stats
	totalRequests  atomic.Int64
	deniedRequests atomic.Int64
)

const (
	defaultMaxArgLength   = 4096
	defaultRequestsPerMin = 120
	defaultBurstSize      = 20
	maxRequestBodySize    = 64 * 1024 // 64 KB
	maxPolicySize         = 1 << 20   // 1 MiB
	maxTokenSize          = 4096
	maxAuditSize          = 256 << 20 // 256 MiB
	maxArgumentNodes      = 10_000
	maxArgumentDepth      = 32
)

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

func policyFilePath() string {
	p := os.Getenv("POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/policy.yaml"
	}
	return p
}

func readPolicyFile() (Policy, error) {
	data, err := readRegularFile(policyFilePath(), maxPolicySize)
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&p); err != nil {
		return Policy{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Policy{}, errors.New("policy must contain exactly one YAML document")
		}
		return Policy{}, fmt.Errorf("parse trailing policy data: %w", err)
	}
	if err := validatePolicy(p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func loadPolicy() error {
	p, err := readPolicyFile()
	if err != nil {
		return err
	}
	digest, err := computePolicyDigest(p)
	if err != nil {
		return err
	}
	policyMu.Lock()
	policy = p
	policyDigest = digest
	policyMu.Unlock()
	log.Printf("policy loaded: default=%s allow=%d deny=%d",
		p.Tools.Default, len(p.Tools.Allow), len(p.Tools.Deny))
	return nil
}

func computePolicyDigest(p Policy) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal policy for digest: %w", err)
	}
	digest := sha256.Sum256(append([]byte("agent-tool-firewall/policy/v1\x00"), data...))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	// #nosec G703 -- this helper only opens explicit policy/credential paths and verifies identity, type, symlink status, and size before returning data.
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symbolic links are not allowed")
	}
	// #nosec G304,G703 -- the operator-selected file is opened only after Lstat and is rejected unless the pre/open/post identities agree and it is a bounded regular file.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// #nosec G703 -- the second Lstat is the post-open anti-symlink/anti-replacement identity check for the explicit operator path.
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, fmt.Errorf("file changed while opening or is a symbolic link")
	}
	if !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if opened.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	return data, nil
}

func validatePolicy(p Policy) error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", p.Version)
	}
	if p.Tools.Default != "deny" {
		return fmt.Errorf("tools.default must be %q", "deny")
	}
	if p.Defaults.Network.RuntimeEgress != "" && p.Defaults.Network.RuntimeEgress != "deny" {
		return errors.New("defaults.network.runtime_egress must be deny when set")
	}
	if len(p.Tools.Allow) > 4096 || len(p.Tools.Deny) > 4096 {
		return errors.New("policy contains too many tool entries")
	}
	if p.Tools.RateLimit.RequestsPerMinute < 0 || p.Tools.RateLimit.RequestsPerMinute > 1_000_000 {
		return errors.New("requests_per_minute must be between 0 and 1000000")
	}
	if p.Tools.RateLimit.BurstSize < 0 || p.Tools.RateLimit.BurstSize > 1_000_000 {
		return errors.New("burst_size must be between 0 and 1000000")
	}
	seen := make(map[string]string, len(p.Tools.Allow)+len(p.Tools.Deny))
	validateEntry := func(entry ToolEntry, list string) error {
		name := strings.TrimSpace(entry.Name)
		if name == "" || name != entry.Name || len(name) > 256 || strings.ContainsAny(name, "\x00\r\n") {
			return fmt.Errorf("%s entry has invalid tool name", list)
		}
		if previous, ok := seen[name]; ok {
			return fmt.Errorf("tool %q appears in both or multiple policy entries (%s and %s)", name, previous, list)
		}
		seen[name] = list
		if len(entry.PathsAllowlist) > 256 || len(entry.PathsDenylist) > 256 || len(entry.ArgsBlacklist) > 256 ||
			len(entry.ArgRules) > 128 {
			return fmt.Errorf("tool %q has too many path or argument rules", name)
		}
		if list == "deny" && (len(entry.PathsAllowlist) > 0 || len(entry.PathsDenylist) > 0 ||
			len(entry.ArgsBlacklist) > 0 || entry.ArgRules != nil || entry.MaxArgLength != 0) {
			return fmt.Errorf("denied tool %q must not define unused constraints", name)
		}
		if entry.MaxArgLength < 0 || entry.MaxArgLength > maxRequestBodySize {
			return fmt.Errorf("tool %q max_arg_length must be between 0 and %d", name, maxRequestBodySize)
		}
		for _, pattern := range append(append([]string{}, entry.PathsAllowlist...), entry.PathsDenylist...) {
			base := strings.TrimSuffix(strings.TrimSuffix(pattern, "/**"), "**")
			if base == "" || !filepath.IsAbs(filepath.Clean(base)) || strings.ContainsRune(pattern, 0) {
				return fmt.Errorf("tool %q has invalid non-absolute path pattern", name)
			}
		}
		for _, blocked := range entry.ArgsBlacklist {
			if blocked == "" || len(blocked) > defaultMaxArgLength || strings.ContainsAny(blocked, "\x00\r\n") {
				return fmt.Errorf("tool %q has invalid empty or oversized blocked argument", name)
			}
		}
		argNames := make(map[string]struct{}, len(entry.ArgRules))
		for _, rule := range entry.ArgRules {
			if rule.Name == "" || len(rule.Name) > 256 || strings.TrimSpace(rule.Name) != rule.Name ||
				strings.ContainsAny(rule.Name, "\x00\r\n") {
				return fmt.Errorf("tool %q has invalid argument rule name", name)
			}
			if _, exists := argNames[rule.Name]; exists {
				return fmt.Errorf("tool %q has duplicate argument rule %q", name, rule.Name)
			}
			argNames[rule.Name] = struct{}{}
			switch rule.Type {
			case "string", "boolean", "number", "integer", "object", "array":
			default:
				return fmt.Errorf("tool %q argument %q has invalid type %q", name, rule.Name, rule.Type)
			}
			if rule.MaxLength < 0 || rule.MaxLength > maxRequestBodySize {
				return fmt.Errorf("tool %q argument %q has invalid max_length", name, rule.Name)
			}
			if len(rule.Pattern) > 4096 || (rule.Pattern != "" && rule.Type != "string") {
				return fmt.Errorf("tool %q argument %q has invalid pattern", name, rule.Name)
			}
			if rule.Pattern != "" {
				if _, err := regexp.Compile(rule.Pattern); err != nil {
					return fmt.Errorf("tool %q argument %q has invalid pattern: %w", name, rule.Name, err)
				}
			}
			if isPathParameter(rule.Name) && rule.Type != "string" {
				return fmt.Errorf("tool %q path argument %q must have type string", name, rule.Name)
			}
		}
		return nil
	}
	for _, entry := range p.Tools.Allow {
		if err := validateEntry(entry, "allow"); err != nil {
			return err
		}
	}
	for _, entry := range p.Tools.Deny {
		if err := validateEntry(entry, "deny"); err != nil {
			return err
		}
	}
	return nil
}

func getPolicy() Policy {
	pol, _ := getPolicySnapshot()
	return pol
}

func getPolicySnapshot() (Policy, string) {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return policy, policyDigest
}

// ---------------------------------------------------------------------------
// Audit logging (structured JSONL)
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Timestamp       string         `json:"timestamp"`
	Event           string         `json:"event"`
	Identity        string         `json:"identity,omitempty"`
	PolicyDigest    string         `json:"policy_digest,omitempty"`
	OldPolicyDigest string         `json:"old_policy_digest,omitempty"`
	NewPolicyDigest string         `json:"new_policy_digest,omitempty"`
	Tool            string         `json:"tool"`
	Params          map[string]any `json:"params,omitempty"`
	Allowed         bool           `json:"allowed"`
	Reason          string         `json:"reason,omitempty"`
}

var sensitiveAuditKeys = map[string]struct{}{
	"args":          {},
	"body":          {},
	"content":       {},
	"context":       {},
	"instruction":   {},
	"input":         {},
	"message":       {},
	"messages":      {},
	"payload":       {},
	"prompt":        {},
	"query":         {},
	"text":          {},
	"authorization": {},
	"credential":    {},
	"password":      {},
	"secret":        {},
	"token":         {},
}

func redactAuditValue(value string) string {
	return fmt.Sprintf("[redacted len=%d]", len(value))
}

func redactAuditCredential() string {
	return "[redacted credential]"
}

func compactAuditKey(name string) string {
	var compact strings.Builder
	compact.Grow(len(name))
	for _, r := range strings.TrimSpace(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			compact.WriteRune(unicode.ToLower(r))
		}
	}
	return compact.String()
}

func isCredentialAuditKey(name string) bool {
	compact := compactAuditKey(name)
	if compact == "auth" || compact == "key" {
		return true
	}
	for _, marker := range []string{
		"password", "passwd", "passphrase", "secret", "token", "credential",
		"authorization", "apikey", "privatekey", "sshkey", "signingkey", "accesskey",
		"sessionkey", "clientkey", "encryptionkey", "decryptionkey", "keymaterial",
		"bearer", "cookie",
	} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	return false
}

func sanitizeAuditParams(params any, pol Policy) map[string]any {
	var root map[string]any
	switch values := params.(type) {
	case map[string]any:
		root = values
	case map[string]string:
		root = make(map[string]any, len(values))
		for key, value := range values {
			root[key] = value
		}
	default:
		return nil
	}
	if len(root) == 0 {
		return nil
	}
	nodes := 0
	clean, ok := sanitizeAuditMap(root, pol, 0, &nodes)
	if !ok {
		return map[string]any{"payload": "[redacted: audit structure limit exceeded]"}
	}
	return clean
}

func sanitizeToolAuditParams(params map[string]any, pol Policy, toolName string) map[string]any {
	clean := sanitizeAuditParams(params, pol)
	if clean == nil {
		return nil
	}
	for _, entry := range pol.Tools.Allow {
		if entry.Name != toolName {
			continue
		}
		for _, rule := range entry.ArgRules {
			if rule.Redact {
				if _, exists := params[rule.Name]; exists {
					clean[rule.Name] = redactAuditCredential()
				}
			}
		}
		break
	}
	return clean
}

func sanitizeAuditMap(values map[string]any, pol Policy, depth int, nodes *int) (map[string]any, bool) {
	if depth > maxArgumentDepth || len(values) > 128 {
		return nil, false
	}
	clean := make(map[string]any, len(values))
	for key, value := range values {
		*nodes++
		if *nodes > maxArgumentNodes {
			return nil, false
		}
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		canonicalKey := normalizeArgumentName(lowerKey)
		compactKey := compactAuditKey(key)
		_, promptLikeKey := sensitiveAuditKeys[lowerKey]
		promptLikeKey = promptLikeKey || containsAuditCategory(canonicalKey,
			"args", "body", "content", "context", "instruction", "input", "message", "messages",
			"payload", "prompt", "query", "text")
		promptLikeKey = promptLikeKey || containsCompactAuditCategory(compactKey,
			"args", "body", "content", "context", "instruction", "input", "message",
			"payload", "prompt", "query", "text")
		responseKey := containsCompactAuditCategory(compactKey, "response", "result", "output")
		if isCredentialAuditKey(key) {
			clean[key] = redactAuditCredential()
			continue
		}
		if (promptLikeKey && !pol.Defaults.Logging.StoreRawPrompts) ||
			(responseKey && !pol.Defaults.Logging.StoreRawResponses) {
			clean[key] = redactAuditAny(value)
			continue
		}
		sanitized, ok := sanitizeAuditNode(value, pol, depth+1, nodes)
		if !ok {
			return nil, false
		}
		clean[key] = sanitized
	}
	return clean, true
}

func containsCompactAuditCategory(name string, categories ...string) bool {
	for _, category := range categories {
		if strings.Contains(name, category) {
			return true
		}
	}
	return false
}

func containsAuditCategory(name string, categories ...string) bool {
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '_' })
	for _, part := range parts {
		for _, category := range categories {
			if part == category {
				return true
			}
		}
	}
	return false
}

func sanitizeAuditNode(value any, pol Policy, depth int, nodes *int) (any, bool) {
	if depth > maxArgumentDepth {
		return nil, false
	}
	switch typed := value.(type) {
	case map[string]any:
		return sanitizeAuditMap(typed, pol, depth, nodes)
	case []any:
		if len(typed) > 4096 {
			return nil, false
		}
		out := make([]any, len(typed))
		for i, item := range typed {
			*nodes++
			if *nodes > maxArgumentNodes {
				return nil, false
			}
			clean, ok := sanitizeAuditNode(item, pol, depth+1, nodes)
			if !ok {
				return nil, false
			}
			out[i] = clean
		}
		return out, true
	case string:
		if len(typed) > 512 {
			return redactAuditValue(typed), true
		}
		return typed, true
	case nil, bool, json.Number, float64:
		return typed, true
	default:
		return redactAuditAny(typed), true
	}
}

func redactAuditAny(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "[redacted]"
	}
	return redactAuditValue(string(data))
}

func initAuditLog() error {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/secure-ai/logs/tool-firewall-audit.jsonl"
	}
	dir := filepath.Dir(auditPath)
	if !filepath.IsAbs(auditPath) {
		return errors.New("audit log path must be absolute")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create audit log directory: %w", err)
	}
	parent, err := os.Lstat(dir)
	if err != nil || parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return errors.New("audit log directory must be a non-symlink directory not writable by group or others")
	}
	if info, err := os.Lstat(auditPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("audit log must be a regular, non-symlink file")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect audit log: %w", err)
	}
	// #nosec G304 -- auditPath is operator-selected but absolute; its parent, file type, identity, permissions, link count, and size are verified before this handle is accepted and before every append.
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	opened, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("inspect opened audit log: %w", err)
	}
	current, err := os.Lstat(auditPath)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) ||
		!opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 || fileLinkCount(opened) > 1 ||
		opened.Size() > maxAuditSize {
		f.Close()
		return fmt.Errorf("audit log must retain identity as an owner-only, single-link regular file under %d bytes", maxAuditSize)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("set audit log permissions: %w", err)
	}
	auditFile = f
	return nil
}

func writeAudit(entry AuditEntry) error {
	if auditFile == nil {
		return errors.New("audit log unavailable")
	}
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	if entry.Event == "" {
		entry.Event = "evaluate"
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	line := append(data, '\n')
	opened, statErr := auditFile.Stat()
	current, pathErr := os.Lstat(auditFile.Name())
	if statErr != nil || pathErr != nil || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, current) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 ||
		fileLinkCount(opened) > 1 || opened.Size()+int64(len(line)) > maxAuditSize {
		return errors.New("audit log identity, permissions, link count, or size limit changed")
	}
	for len(line) > 0 {
		n, err := auditFile.Write(line)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		line = line[n:]
	}
	return auditFile.Sync()
}

func fileLinkCount(info os.FileInfo) uint64 {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0
	}
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 0
	}
	if field.Kind() >= reflect.Uint && field.Kind() <= reflect.Uint64 {
		return field.Uint()
	}
	if field.Kind() >= reflect.Int && field.Kind() <= reflect.Int64 {
		signedLinks := field.Int()
		if signedLinks > 0 {
			return uint64(signedLinks)
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func checkRateLimit(pol Policy) bool {
	rpm := pol.Tools.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRequestsPerMin
	}

	burst := pol.Tools.RateLimit.BurstSize
	if burst <= 0 {
		burst = defaultBurstSize
	}
	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()
	if rateLast.IsZero() || rateRPM != rpm || rateBurst != burst {
		rateLast = now
		rateTokens = float64(burst)
		rateRPM = rpm
		rateBurst = burst
	} else {
		rateTokens += now.Sub(rateLast).Seconds() * float64(rpm) / 60
		if rateTokens > float64(burst) {
			rateTokens = float64(burst)
		}
		rateLast = now
	}
	if rateTokens < 1 {
		return false
	}
	rateTokens--
	return true
}

// ---------------------------------------------------------------------------
// Path security
// ---------------------------------------------------------------------------

// cleanAndResolvePath canonicalizes a path, catching traversal attempts.
func cleanAndResolvePath(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	// Reject null bytes (path injection via null terminator)
	if strings.ContainsRune(raw, 0) {
		return "", fmt.Errorf("path contains null byte")
	}
	decoded, err := decodePath(raw)
	if err != nil {
		return "", err
	}
	if containsUnicodePathConfusable(decoded) {
		return "", fmt.Errorf("path contains unicode path confusable")
	}
	if !filepath.IsAbs(decoded) {
		return "", fmt.Errorf("path must be absolute")
	}
	cleaned := filepath.Clean(decoded)
	// Resolve to absolute to catch ../../../etc/shadow style attacks
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path: %w", err)
	}
	return resolvePath(abs)
}

func decodePath(raw string) (string, error) {
	decoded := raw
	for i := 0; i < 3; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return "", fmt.Errorf("path contains invalid percent-encoding")
		}
		if next == decoded {
			return decoded, nil
		}
		if strings.ContainsRune(next, 0) {
			return "", fmt.Errorf("path contains null byte")
		}
		decoded = next
	}
	return "", fmt.Errorf("path is percent-encoded too deeply")
}

func containsUnicodePathConfusable(raw string) bool {
	for _, r := range raw {
		switch r {
		case '\u2044', '\u2215', '\u2216', '\u29f8', '\uff0e', '\uff0f', '\uff3c', '\ufffd':
			return true
		}
		if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
			return true
		}
	}
	return false
}

func resolvePath(abs string) (string, error) {
	// Resolve symlinks for the deepest existing prefix so allowlist checks
	// apply to the real target, not just the lexical path.
	cursor := abs
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(cursor)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("cannot resolve path: %w", err)
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			// Nothing existed on disk; fall back to the canonical absolute path.
			return filepath.Clean(abs), nil
		}
		suffix = append(suffix, filepath.Base(cursor))
		cursor = parent
	}
}

func normalizeMatchPath(raw string) string {
	clean := filepath.Clean(raw)
	slash := filepath.ToSlash(clean)
	if vol := filepath.VolumeName(clean); vol != "" {
		slash = strings.ToLower(filepath.ToSlash(vol)) + strings.TrimPrefix(slash, vol)
	}
	return slash
}

func pathMatchCandidates(raw string) []string {
	norm := normalizeMatchPath(raw)
	candidates := []string{norm}
	if vol := filepath.VolumeName(filepath.Clean(raw)); vol != "" {
		volNorm := strings.ToLower(filepath.ToSlash(vol))
		trimmed := strings.TrimPrefix(norm, volNorm)
		if trimmed != "" {
			candidates = append(candidates, trimmed)
		}
	}
	return candidates
}

func hasPathPrefix(path, prefix string) bool {
	prefixNorm := normalizeMatchPath(prefix)
	for _, candidate := range pathMatchCandidates(path) {
		if candidate == prefixNorm || strings.HasPrefix(candidate, prefixNorm+"/") {
			return true
		}
	}
	return false
}

// matchesGlob checks if a path matches an allowlist pattern.
// Supports trailing ** for recursive match (prefix match) and exact prefix match.
func matchesGlob(path, pattern string) bool {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		prefix = filepath.Clean(prefix)
		return hasPathPrefix(path, prefix)
	}
	if strings.HasSuffix(pattern, "**") {
		prefix := strings.TrimSuffix(pattern, "**")
		prefix = filepath.Clean(prefix)
		return hasPathPrefix(path, prefix)
	}
	return hasPathPrefix(path, pattern)
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

func effectiveTypedParams(req ToolCallRequest) map[string]any {
	if req.TypedParams != nil {
		return req.TypedParams
	}
	values := make(map[string]any, len(req.Params))
	for key, value := range req.Params {
		values[key] = value
	}
	return values
}

func encodeArgumentForInspection(value any) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

func argumentTreeContainsPattern(value any, pattern string, depth int, nodes *int) (bool, error) {
	if depth > maxArgumentDepth {
		return false, errors.New("argument tree exceeds the depth limit")
	}
	(*nodes)++
	if *nodes > maxArgumentNodes {
		return false, errors.New("argument tree exceeds the node limit")
	}
	contains := func(text string) bool {
		return strings.Contains(strings.ToLower(text), pattern)
	}
	switch typed := value.(type) {
	case nil:
		return false, nil
	case string:
		return contains(typed), nil
	case json.Number:
		return contains(string(typed)), nil
	case float64:
		return contains(strconv.FormatFloat(typed, 'g', -1, 64)), nil
	case bool:
		return contains(strconv.FormatBool(typed)), nil
	case map[string]any:
		if len(typed) > 128 {
			return false, errors.New("argument object exceeds the member limit")
		}
		for key, nested := range typed {
			if contains(key) {
				return true, nil
			}
			matched, err := argumentTreeContainsPattern(nested, pattern, depth+1, nodes)
			if err != nil || matched {
				return matched, err
			}
		}
		return false, nil
	case []any:
		if len(typed) > 4096 {
			return false, errors.New("argument array exceeds the item limit")
		}
		for _, nested := range typed {
			matched, err := argumentTreeContainsPattern(nested, pattern, depth+1, nodes)
			if err != nil || matched {
				return matched, err
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("unsupported argument value type %T", value)
	}
}

func validateArgs(req ToolCallRequest, entry ToolEntry) (bool, string) {
	params := effectiveTypedParams(req)
	maxLen := entry.MaxArgLength
	if maxLen <= 0 {
		maxLen = defaultMaxArgLength
	}

	rules := make(map[string]ToolArgRule, len(entry.ArgRules))
	for _, rule := range entry.ArgRules {
		rules[rule.Name] = rule
	}
	for key, val := range params {
		rule, declared := rules[key]
		if entry.ArgRules != nil && !declared {
			return false, fmt.Sprintf("argument %q is not declared by this tool policy", key)
		}
		if !declared && dangerousArgumentName(key) && !(isPathParameter(key) &&
			(len(entry.PathsAllowlist) > 0 || len(entry.PathsDenylist) > 0)) {
			return false, fmt.Sprintf("dangerous argument %q requires an explicit typed policy rule", key)
		}
		encoded, err := encodeArgumentForInspection(val)
		if err != nil {
			return false, fmt.Sprintf("argument %q cannot be encoded", key)
		}
		// Length check
		valueLength := len(encoded)
		if text, ok := val.(string); ok {
			valueLength = len(text)
		}
		if valueLength > maxLen {
			return false, fmt.Sprintf("argument %q exceeds max length (%d > %d)", key, valueLength, maxLen)
		}

		// Blocked argument patterns (e.g., shell injection attempts)
		encodedLower := strings.ToLower(string(encoded))
		for _, blocked := range entry.ArgsBlacklist {
			blockedLower := strings.ToLower(blocked)
			nodes := 0
			nestedMatch, inspectErr := argumentTreeContainsPattern(val, blockedLower, 0, &nodes)
			if inspectErr != nil {
				return false, fmt.Sprintf("argument %q cannot be safely inspected", key)
			}
			if nestedMatch || strings.Contains(encodedLower, blockedLower) {
				return false, fmt.Sprintf("argument %q contains blocked pattern %q", key, blocked)
			}
		}
		if declared {
			if ok, reason := validateTypedArgument(key, val, rule); !ok {
				return false, reason
			}
		}
	}
	for _, rule := range entry.ArgRules {
		if _, exists := params[rule.Name]; rule.Required && !exists {
			return false, fmt.Sprintf("required argument %q is missing", rule.Name)
		}
	}
	return true, ""
}

func validateTypedArgument(name string, value any, rule ToolArgRule) (bool, string) {
	typeOK := false
	switch rule.Type {
	case "string":
		_, typeOK = value.(string)
	case "boolean":
		_, typeOK = value.(bool)
	case "number":
		switch value.(type) {
		case json.Number, float64:
			typeOK = true
		}
	case "integer":
		switch typed := value.(type) {
		case json.Number:
			_, err := strconv.ParseInt(string(typed), 10, 64)
			typeOK = err == nil
		case float64:
			typeOK = typed == float64(int64(typed))
		}
	case "object":
		_, typeOK = value.(map[string]any)
	case "array":
		_, typeOK = value.([]any)
	}
	if !typeOK {
		return false, fmt.Sprintf("argument %q must have JSON type %s", name, rule.Type)
	}
	if rule.MaxLength > 0 {
		length := 0
		switch typed := value.(type) {
		case string:
			length = len(typed)
		case []any:
			length = len(typed)
		case map[string]any:
			length = len(typed)
		default:
			encoded, _ := json.Marshal(value)
			length = len(encoded)
		}
		if length > rule.MaxLength {
			return false, fmt.Sprintf("argument %q exceeds typed max_length %d", name, rule.MaxLength)
		}
	}
	if rule.Pattern != "" {
		valueString := value.(string)
		matched, err := regexp.MatchString(rule.Pattern, valueString)
		if err != nil || !matched {
			return false, fmt.Sprintf("argument %q does not match its required pattern", name)
		}
	}
	return true, ""
}

func dangerousArgumentName(name string) bool {
	if isCredentialAuditKey(name) {
		return true
	}
	canonical := normalizeArgumentName(name)
	switch canonical {
	case "cmd", "command", "shell", "exec", "executable", "script", "code", "program",
		"url", "uri", "endpoint", "host", "headers", "authorization", "env", "environment",
		"cwd", "working_directory", "workingdirectory", "body", "payload", "content", "template",
		"shellcommand", "execargs", "requesturl", "httpheaders":
		return true
	}
	for _, part := range strings.FieldsFunc(canonical, func(r rune) bool { return r == '_' }) {
		switch part {
		case "cmd", "command", "shell", "exec", "executable", "script", "code", "program",
			"url", "uri", "endpoint", "host", "headers", "authorization", "env", "environment",
			"cwd", "body", "payload", "content", "template":
			return true
		}
	}
	return isPathParameter(name)
}

func normalizeArgumentName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var normalized strings.Builder
	normalized.Grow(len(name))
	lastSeparator := false
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			normalized.WriteRune(r)
			lastSeparator = false
			continue
		}
		if !lastSeparator {
			normalized.WriteByte('_')
			lastSeparator = true
		}
	}
	return strings.Trim(normalized.String(), "_")
}

func validateToolCall(req ToolCallRequest) (bool, string) {
	if req.Tool == "" || len(req.Tool) > 256 || strings.TrimSpace(req.Tool) != req.Tool ||
		strings.ContainsAny(req.Tool, "\x00\r\n") {
		return false, "invalid tool name"
	}
	if len(effectiveTypedParams(req)) > 128 {
		return false, "too many parameters"
	}
	params := effectiveTypedParams(req)
	for key := range params {
		if key == "" || len(key) > 256 || strings.TrimSpace(key) != key || strings.ContainsAny(key, "\x00\r\n") {
			return false, "invalid parameter name"
		}
	}
	nodes := 0
	if !validateArgumentTree(params, 0, &nodes) {
		return false, "invalid or excessively nested parameter value"
	}
	return true, ""
}

func validateArgumentTree(value any, depth int, nodes *int) bool {
	if depth > maxArgumentDepth {
		return false
	}
	*nodes++
	if *nodes > maxArgumentNodes {
		return false
	}
	switch typed := value.(type) {
	case nil, bool, string:
		return true
	case json.Number:
		_, err := strconv.ParseFloat(string(typed), 64)
		return err == nil
	case float64:
		return true
	case map[string]any:
		if len(typed) > 128 {
			return false
		}
		for key, nested := range typed {
			if key == "" || len(key) > 256 || strings.ContainsAny(key, "\x00\r\n") ||
				!validateArgumentTree(nested, depth+1, nodes) {
				return false
			}
		}
		return true
	case []any:
		if len(typed) > 4096 {
			return false
		}
		for _, nested := range typed {
			if !validateArgumentTree(nested, depth+1, nodes) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isPathParameter(key string) bool {
	switch normalizeArgumentName(key) {
	case "path", "file", "filepath", "file_path", "filename", "directory", "dir", "root", "cwd",
		"target", "destination", "source", "input_path", "output_path", "source_path", "destination_path":
		return true
	case "inputpath", "outputpath", "sourcepath", "destinationpath", "workingdirectory", "working_directory":
		return true
	default:
		return false
	}
}

func checkPathConstraints(params map[string]string, entry ToolEntry) (bool, string) {
	found := false
	for key, raw := range params {
		if !isPathParameter(key) {
			continue
		}
		if raw == "" {
			return false, "path parameter must not be empty"
		}
		found = true
		resolved, err := cleanAndResolvePath(raw)
		if err != nil {
			return false, "invalid path: " + err.Error()
		}
		for _, denied := range entry.PathsDenylist {
			if matchesGlob(resolved, denied) {
				return false, "path matches denylist"
			}
		}
		if len(entry.PathsAllowlist) > 0 {
			allowed := false
			for _, pattern := range entry.PathsAllowlist {
				if matchesGlob(resolved, pattern) {
					allowed = true
					break
				}
			}
			if !allowed {
				return false, "path not in allowlist"
			}
		}
	}
	if (len(entry.PathsAllowlist) > 0 || len(entry.PathsDenylist) > 0) && !found {
		return false, "required path parameter missing"
	}
	return true, ""
}

func normalizeParams(raw map[string]any) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	normalized := make(map[string]string, len(raw))
	for key, val := range raw {
		switch typed := val.(type) {
		case nil:
			normalized[key] = ""
		case string:
			normalized[key] = typed
		case bool, float64:
			normalized[key] = fmt.Sprint(typed)
		default:
			encoded, err := json.Marshal(typed)
			if err != nil {
				normalized[key] = fmt.Sprint(typed)
				continue
			}
			normalized[key] = string(encoded)
		}
	}
	return normalized
}

// ---------------------------------------------------------------------------
// Core evaluation
// ---------------------------------------------------------------------------

func evaluateTool(req ToolCallRequest) ToolCallResponse {
	pol, _ := getPolicySnapshot()
	return evaluateToolWithPolicy(req, pol)
}

func evaluateToolWithPolicy(req ToolCallRequest, pol Policy) ToolCallResponse {
	if ok, reason := validateToolCall(req); !ok {
		return ToolCallResponse{Allowed: false, Reason: reason}
	}

	// Rate limit check
	if !checkRateLimit(pol) {
		return ToolCallResponse{Allowed: false, Reason: "rate limit exceeded"}
	}

	// Check deny list first (deny always wins)
	for _, denied := range pol.Tools.Deny {
		if denied.Name == req.Tool {
			return ToolCallResponse{Allowed: false, Reason: "tool is explicitly denied"}
		}
	}

	// Policy validation guarantees default-deny. Keep evaluation fail-closed even
	// if an invalid policy is injected into memory by a test or future refactor.
	var matched *ToolEntry
	for i, allowed := range pol.Tools.Allow {
		if allowed.Name == req.Tool {
			matched = &pol.Tools.Allow[i]
			break
		}
	}
	if matched == nil {
		return ToolCallResponse{Allowed: false, Reason: "tool not in allowlist"}
	}
	if ok, reason := validateArgs(req, *matched); !ok {
		return ToolCallResponse{Allowed: false, Reason: reason}
	}
	if ok, reason := checkPathConstraints(normalizeParams(effectiveTypedParams(req)), *matched); !ok {
		return ToolCallResponse{Allowed: false, Reason: reason}
	}
	return ToolCallResponse{Allowed: true}
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var wire toolCallRequestWire
	if err := decodeRequestJSON(w, r, &wire, maxRequestBodySize); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	rawParams := wire.Params
	if wire.Params != nil && wire.Args != nil {
		http.Error(w, "params and args cannot both be supplied", http.StatusBadRequest)
		return
	}
	if rawParams == nil && wire.Args != nil {
		rawParams = wire.Args
	}
	req := ToolCallRequest{
		Tool:        wire.Tool,
		Params:      normalizeParams(rawParams),
		TypedParams: rawParams,
	}

	totalRequests.Add(1)

	// Keep the exact policy snapshot active through both evaluation and its
	// durable audit append. A reload takes the exclusive side of this lock and
	// therefore cannot publish its audit event out of order with evaluations.
	policyMu.RLock()
	pol, digest := policy, policyDigest
	resp := evaluateToolWithPolicy(req, pol)

	if !resp.Allowed {
		deniedRequests.Add(1)
	}

	// Structured logging
	log.Printf("tool-firewall: tool=%s allowed=%t reason=%q", req.Tool, resp.Allowed, resp.Reason)

	// Audit log
	if err := writeAudit(AuditEntry{
		Event:        "evaluate",
		Identity:     authenticatedIdentity(r),
		PolicyDigest: digest,
		Tool:         req.Tool,
		Params:       sanitizeToolAuditParams(req.TypedParams, pol, req.Tool),
		Allowed:      resp.Allowed,
		Reason:       resp.Reason,
	}); err != nil {
		policyMu.RUnlock()
		log.Printf("tool-firewall: audit write failed: %v", err)
		http.Error(w, "audit service unavailable", http.StatusServiceUnavailable)
		return
	}
	policyMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func decodeRequestJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	newPolicy, err := readPolicyFile()
	if err != nil {
		log.Printf("policy reload failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "policy reload failed"})
		return
	}
	newDigest, err := computePolicyDigest(newPolicy)
	if err != nil {
		log.Printf("policy digest failed: %v", err)
		http.Error(w, "policy reload failed", http.StatusInternalServerError)
		return
	}

	// Serialize the entire commit transaction: identify the active policy,
	// append the transition record, and only then publish the new policy.
	policyMu.Lock()
	oldDigest := policyDigest
	if err := writeAudit(AuditEntry{
		Event:           "reload",
		Identity:        authenticatedIdentity(r),
		OldPolicyDigest: oldDigest,
		NewPolicyDigest: newDigest,
		Allowed:         true,
		Reason:          "validated policy reload",
	}); err != nil {
		policyMu.Unlock()
		log.Printf("policy reload audit failed: %v", err)
		http.Error(w, "audit service unavailable", http.StatusServiceUnavailable)
		return
	}
	policy = newPolicy
	policyDigest = newDigest
	policyMu.Unlock()
	log.Printf("policy reloaded successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pol := getPolicy()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"default_action":  pol.Tools.Default,
		"allowed_tools":   len(pol.Tools.Allow),
		"denied_tools":    len(pol.Tools.Deny),
		"total_requests":  totalRequests.Load(),
		"denied_requests": deniedRequests.Load(),
	})
}

func newToolFirewallMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/evaluate", requireRole(roleEvaluator, handleEvaluate))
	mux.HandleFunc("/v1/stats", requireRole(roleObserver, handleStats))
	mux.HandleFunc("/v1/reload", requireRole(roleAdministrator, handleReload))
	return mux
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func validateBindAddress(bind string) error {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return fmt.Errorf("invalid host:port: %w", err)
	}
	loopback := strings.EqualFold(host, "localhost")
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	if !loopback && os.Getenv("ALLOW_REMOTE_BIND") != "true" {
		return errors.New("non-loopback bind requires ALLOW_REMOTE_BIND=true")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if err := loadPolicy(); err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}

	if err := initAuditLog(); err != nil {
		log.Fatalf("audit logging unavailable: %v", err)
	}
	defer func() {
		if auditFile != nil {
			_ = auditFile.Close()
		}
	}()
	credentials, err := loadCredentialSet()
	if err != nil {
		log.Fatalf("credential authentication unavailable: %v", err)
	}
	_, startupDigest := getPolicySnapshot()
	if err := writeAudit(AuditEntry{Event: "startup", PolicyDigest: startupDigest, Allowed: true, Reason: "service initialized"}); err != nil {
		log.Fatalf("audit logging unavailable: %v", err)
	}

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8475"
	}
	if err := validateBindAddress(bind); err != nil {
		log.Fatalf("invalid bind address: %v", err)
	}

	log.Printf("secure-ai-tool-firewall listening on %s", bind)
	server := &http.Server{
		Addr:              bind,
		Handler:           securityHeaders(authenticatedHandler(newToolFirewallMux(), credentials)),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down tool-firewall...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	log.Println("tool-firewall stopped")
}

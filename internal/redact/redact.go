// Package redact removes obvious secrets from command lines before they are
// written to logs, printed, or shown in notifications. Command lines often
// carry tokens (--token=..., API keys in env-style args, credentials in URLs).
//
// This is a best-effort filter for common shapes, not a guarantee: a secret
// passed as a bare positional argument cannot be recognised.
package redact

import "regexp"

// Mask replaces a secret value.
const Mask = "[REDACTED]"

// secretWord matches option or variable names that usually hold a secret.
const secretWord = `(?:token|pass(?:wd|word|phrase)?|pwd|secret|api[-_]?key|apikey|access[-_]?key|private[-_]?key|auth|credential|cookie|session[-_]?key|signature)`

type rule struct {
	re   *regexp.Regexp
	repl string
}

var rules = []rule{
	// HTTP authorization headers: "Authorization: Bearer abc", "authorization=basic abc".
	{regexp.MustCompile(`(?i)(authorization["']?\s*[:=]\s*["']?)(?:(bearer|basic|token|digest)\s+)?[^\s"',;]+`), "${1}${2} " + Mask},
	// Bare bearer tokens.
	{regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}`), "${1} " + Mask},
	// Options: --token=x, --api-key x, -password=x.
	{regexp.MustCompile(`(?i)(--?[a-z0-9_.-]*` + secretWord + `[a-z0-9_.-]*)(=|\s+)("[^"]*"|'[^']*'|[^\s"'&]+)`), "${1}${2}" + Mask},
	// key=value pairs in env-style args and query strings: GITHUB_TOKEN=x, ?password=x&.
	{regexp.MustCompile(`(?i)\b([a-z0-9_.]*` + secretWord + `[a-z0-9_]*)=("[^"]*"|'[^']*'|[^\s"'&]+)`), "${1}=" + Mask},
	// Credentials embedded in URLs: scheme://user:pass@host.
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`), "${1}" + Mask + "@"},
	// Well-known token shapes.
	{regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b`), Mask},
	// JSON Web Tokens.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`), Mask},
}

// String returns s with recognised secrets replaced by Mask.
func String(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

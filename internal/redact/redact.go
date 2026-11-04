// Package redact removes obvious secrets from command lines before they are
// written to logs, printed, or shown in notifications. Command lines often
// carry tokens (--token=..., API keys in env-style args, credentials in URLs).
//
// This is a best-effort filter for common shapes, not a guarantee. Two
// limits matter in practice: a secret passed as a bare positional argument
// cannot be recognised, and because ps and /proc drop the quotes around
// arguments, only the first word of a multi-word secret value is masked.
package redact

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Mask replaces a secret value.
const Mask = "[REDACTED]"

// secretSegments are name parts that mark a value as secret. Names are
// split on "-", "_", ".", ":" and camelCase, so "--tokenizer-path" is not a
// secret but "--auth-token", "GITHUB_TOKEN" and "accessToken" are.
var secretSegments = map[string]bool{
	"token": true, "tokens": true, "pass": true, "passwd": true, "password": true,
	"passphrase": true, "pwd": true, "secret": true, "secrets": true, "apikey": true,
	"auth": true, "authorization": true, "credential": true, "credentials": true, "cookie": true,
	"signature": true, "accesstoken": true, "authtoken": true, "apitoken": true,
	"privatekey": true, "sessionkey": true, "accesskey": true, "secretkey": true,
}

// keyPairs are two adjacent segments that together mean a secret.
var keyPairs = map[[2]string]bool{
	{"api", "key"}: true, {"access", "key"}: true, {"private", "key"}: true,
	{"session", "key"}: true, {"secret", "key"}: true, {"client", "key"}: true,
	{"master", "key"}: true, {"signing", "key"}: true, {"encryption", "key"}: true,
}

// harmlessLast are final segments that turn a secret-ish name into one whose
// value is not itself secret: --password-file /path, --password-store=basic.
var harmlessLast = map[string]bool{
	"file": true, "path": true, "dir": true, "store": true, "prompt": true,
	"stdin": true, "env": true, "command": true, "cmd": true, "helper": true,
	"type": true, "mode": true, "policy": true, "length": true, "len": true,
	"required": true, "manager": true, "source": true, "url": true, "endpoint": true,
	"header": true, "name": true, "id": true, "method": true, "scheme": true,
	"timeout": true, "ttl": true, "expiry": true, "expires": true,
}

func segments(name string) []string {
	var segs []string
	var cur []rune
	prevLower := false
	flush := func() {
		if len(cur) > 0 {
			segs = append(segs, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for _, r := range name {
		switch {
		case r == '-' || r == '_' || r == '.' || r == ':' || r == ' ':
			flush()
			prevLower = false
		case unicode.IsUpper(r) && prevLower: // camelCase boundary
			flush()
			cur = append(cur, r)
			prevLower = false
		default:
			cur = append(cur, r)
			prevLower = unicode.IsLower(r) || unicode.IsDigit(r)
		}
	}
	flush()
	return segs
}

// SecretName reports whether an option, variable or header name usually
// holds a secret value.
func SecretName(name string) bool {
	segs := segments(strings.TrimLeft(name, "-"))
	if len(segs) == 0 || segs[0] == "no" || harmlessLast[segs[len(segs)-1]] {
		return false
	}
	for i, s := range segs {
		if secretSegments[s] {
			return true
		}
		if i > 0 && keyPairs[[2]string{segs[i-1], s}] {
			return true
		}
	}
	return false
}

// valueWords are authorization schemes that precede the real secret.
var valueWords = map[string]bool{"bearer": true, "basic": true, "token": true, "digest": true}

// Program-specific short options whose value is a password.
var (
	attachedPass = map[string]string{ // -pSECRET
		"mysql": "-p", "mysqldump": "-p", "mysqladmin": "-p", "mariadb": "-p", "mariadb-dump": "-p",
	}
	separatePass = map[string]map[string]bool{ // -p SECRET
		"sshpass":    {"-p": true},
		"redis-cli":  {"-a": true},
		"valkey-cli": {"-a": true},
	}
	userPass = map[string]bool{"curl": true, "wget": true, "http": true} // -u user:pass
)

var (
	// Credentials embedded in URLs: scheme://user:pass@host or a bare token
	// as userinfo. The match runs to the last "@" before the path, so "@" in
	// a password does not leak the rest of it.
	urlUserinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s?#]*@`)
	// Query parameters: ?password=x&.
	queryParam = regexp.MustCompile(`([?&;])([A-Za-z0-9_.-]+)=([^&\s#]*)`)
	// JSON members: "password": "x".
	jsonMember = regexp.MustCompile(`"([A-Za-z0-9_.-]+)"\s*:\s*"((?:[^"\\]|\\.)*)"`)
	// Bare bearer tokens anywhere.
	bearer = regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}`)
	// Well-known token shapes.
	tokenShapes = regexp.MustCompile(`\b(?:` + strings.Join([]string{
		`gh[pousr]_[A-Za-z0-9]{20,}`, `github_pat_[A-Za-z0-9_]{20,}`,
		`sk-[A-Za-z0-9_-]{20,}`, `[sr]k_(?:live|test)_[A-Za-z0-9]{10,}`,
		`xox[abprse]-[A-Za-z0-9-]{10,}`, `(?:AKIA|ASIA)[0-9A-Z]{16}`, `AIza[0-9A-Za-z_-]{30,}`,
		`glpat-[A-Za-z0-9_-]{20,}`, `npm_[A-Za-z0-9]{30,}`, `hf_[A-Za-z0-9]{30,}`,
		`ya29\.[A-Za-z0-9_-]{20,}`, `SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`,
		`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`, // JWT
	}, "|") + `)`)
	slackHook = regexp.MustCompile(`(hooks\.slack\.com/services/)[A-Za-z0-9/]+`)
	wordRe    = regexp.MustCompile(`\S+`)
)

// String returns s with recognised secrets replaced by Mask.
func String(s string) string {
	if s == "" {
		return s
	}
	s = urlUserinfo.ReplaceAllString(s, "${1}"+Mask+"@")
	s = queryParam.ReplaceAllStringFunc(s, func(m string) string {
		p := queryParam.FindStringSubmatch(m)
		if SecretName(p[2]) {
			return p[1] + p[2] + "=" + Mask
		}
		return m
	})
	s = jsonMember.ReplaceAllStringFunc(s, func(m string) string {
		p := jsonMember.FindStringSubmatch(m)
		if SecretName(p[1]) {
			return `"` + p[1] + `":"` + Mask + `"`
		}
		return m
	})
	s = words(s)
	s = bearer.ReplaceAllString(s, "${1} "+Mask)
	s = tokenShapes.ReplaceAllString(s, Mask)
	s = slackHook.ReplaceAllString(s, "${1}"+Mask)
	return s
}

// words applies the argument-level rules to whitespace-separated words.
func words(s string) string {
	spans := wordRe.FindAllStringIndex(s, -1)
	w := make([]string, len(spans))
	for i, sp := range spans {
		w[i] = s[sp[0]:sp[1]]
	}
	// maskNext masks the value after word i and returns the index of its
	// last word. A value still in quotes (from a raw Windows command line)
	// is masked up to its closing quote.
	maskNext := func(i int) int {
		if i+1 >= len(w) {
			return i
		}
		j := i + 1
		if valueWords[strings.ToLower(w[j])] && j+1 < len(w) {
			j++ // "Authorization: Bearer X": mask X
		}
		start := j
		if q := w[j][0]; (q == '"' || q == '\'') && (len(w[j]) == 1 || !strings.HasSuffix(w[j], string(q))) {
			for j+1 < len(w) && !strings.HasSuffix(w[j], string(q)) {
				j++
			}
		}
		for k := start; k <= j; k++ {
			w[k] = ""
		}
		w[start] = Mask
		return j
	}
	prog := ""
	for i := 0; i < len(w); i++ {
		word := w[i]
		if base := strings.ToLower(filepath.Base(strings.ReplaceAll(word, `\`, "/"))); !strings.HasPrefix(word, "-") {
			base = strings.TrimSuffix(base, ".exe")
			if _, ok := attachedPass[base]; ok {
				prog = base
			} else if _, ok := separatePass[base]; ok {
				prog = base
			} else if userPass[base] {
				prog = base
			}
		}
		switch {
		case strings.HasPrefix(word, "-"):
			if flag, ok := attachedPass[prog]; ok && strings.HasPrefix(word, flag) && len(word) > len(flag) && !strings.HasPrefix(word, "--") {
				w[i] = flag + Mask
				continue
			}
			if separatePass[prog][word] {
				i = maskNext(i)
				continue
			}
			if userPass[prog] && (word == "-u" || word == "--user" || word == "--proxy-user") && i+1 < len(w) {
				if k := strings.IndexByte(w[i+1], ':'); k >= 0 {
					w[i+1] = w[i+1][:k+1] + Mask
				}
				i++
				continue
			}
			if k := strings.IndexAny(word, "=:"); k > 0 {
				if SecretName(word[:k]) && word[k+1:] != "" {
					w[i] = word[:k+1] + Mask
				}
				continue
			}
			if SecretName(word) && i+1 < len(w) && !strings.HasPrefix(w[i+1], "-") {
				i = maskNext(i)
			}
		case strings.HasSuffix(word, ":") && len(strings.TrimLeft(word, `"'`)) > 1:
			// HTTP header style: "X-Api-Key: value", "Authorization: Bearer x".
			if SecretName(strings.TrimLeft(word[:len(word)-1], `"'`)) {
				i = maskNext(i)
			}
		default:
			// NAME=VALUE (env style) or NAME:VALUE (wrangler --var KEY:VALUE,
			// "Authorization:Basic x").
			if k := strings.IndexAny(word, "=:"); k > 0 && !strings.Contains(word[:k], "/") {
				if SecretName(strings.TrimLeft(word[:k], `"'`)) && word[k+1:] != "" {
					w[i] = word[:k+1] + Mask
					if valueWords[strings.ToLower(word[k+1:])] && i+1 < len(w) {
						w[i] = word
						w[i+1] = Mask
						i++
					}
				}
			}
		}
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for i, sp := range spans {
		if w[i] != "" {
			b.WriteString(s[last:sp[0]])
			b.WriteString(w[i])
		}
		last = sp[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// Display prepares untrusted text for a terminal or log: secrets are
// masked and control characters (which could move the cursor or rewrite
// earlier output) become spaces.
func Display(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	return String(s)
}

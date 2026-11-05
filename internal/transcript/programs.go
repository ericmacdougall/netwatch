package transcript

import (
	"path"
	"regexp"
	"strings"
)

// Program extraction: the names of the executables a shell command invokes.
// Only these normalized names are kept on a Call, never the command text,
// so incident ranking can compare them with a process name.
//
// Rules:
//   - the first word of each command segment (split on ; & | newline,
//     parentheses, backticks and $( ) is a program, after skipping
//     VAR=value assignments, shell keywords and wrappers (env, sudo, time,
//     nohup, nice, command, exec, caffeinate, timeout N);
//   - the program name is the basename;
//   - for an interpreter (python*, node, ruby, perl, bash, sh, zsh, php,
//     deno, bun) `-m module` adds the module's top-level name and the first
//     non-flag argument adds the script's base name without extension;
//   - `sh|bash|zsh -c 'payload'` is parsed once more, to depth 2.

const (
	maxPrograms  = 24
	maxArgNames  = 48
	maxProgDepth = 2
)

var (
	assignRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	versionRE = regexp.MustCompile(`^([a-z][a-z_-]*?)[-_.]?[0-9][0-9.]*$`)
	keywords  = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "fi": true, "do": true, "done": true,
		"while": true, "until": true, "for": true, "in": true, "!": true, "case": true, "esac": true, "{": true, "}": true}
	wrappers = map[string]bool{"env": true, "sudo": true, "time": true, "nohup": true, "nice": true, "command": true,
		"exec": true, "caffeinate": true, "builtin": true, "timeout": true}
	interpreters = map[string]bool{"python": true, "node": true, "nodejs": true, "ruby": true, "perl": true,
		"bash": true, "sh": true, "zsh": true, "php": true, "deno": true, "bun": true}
	// argFlags lists wrapper flags that take a separate argument.
	argFlags = map[string]map[string]bool{
		"sudo":    {"-u": true, "-g": true, "-U": true, "-h": true, "-p": true, "-C": true, "-D": true, "-r": true, "-t": true},
		"nice":    {"-n": true},
		"env":     {"-u": true, "-C": true, "-S": true},
		"timeout": {"-s": true, "-k": true},
	}
	shells = map[string]bool{"bash": true, "sh": true, "zsh": true}
)

// NormalizeName lowercases a program or process name and strips a trailing
// version suffix, so "python3.12" and "Python" both become "python".
func NormalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if m := versionRE.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return s
}

// Programs returns the normalized names of the programs cmd invokes, in
// order of appearance, without duplicates and bounded.
func Programs(cmd string) []string {
	var out []string
	seen := map[string]bool{}
	collect(cmd, 0, func(n string) {
		n = NormalizeName(n)
		if n != "" && !seen[n] && len(out) < maxPrograms {
			seen[n] = true
			out = append(out, n)
		}
	}, func(string) {})
	return out
}

// ArgNames returns the normalized base names of standalone arguments (not
// inside quotes, not flags, not assignments) of the commands in cmd. A name
// here that equals a process name is a "weak" match: it may be a program
// exec'd through a wrapper, or just a file with that name.
func ArgNames(cmd string) []string {
	var out []string
	seen := map[string]bool{}
	collect(cmd, 0, func(string) {}, func(n string) {
		n = NormalizeName(n)
		if n != "" && !seen[n] && len(out) < maxArgNames {
			seen[n] = true
			out = append(out, n)
		}
	})
	return out
}

// splitSegments tokenizes cmd into segments of words, honouring quotes.
// word is one shell word; q is set when any part of it was quoted or
// escaped, which makes it not a standalone token.
type word struct {
	s string
	q bool
}

func splitSegments(cmd string) [][]word {
	var segs [][]word
	var words []word
	var cur strings.Builder
	inWord, quoted := false, false
	flushWord := func() {
		if inWord {
			words = append(words, word{cur.String(), quoted})
			cur.Reset()
			inWord, quoted = false, false
		}
	}
	flushSeg := func() {
		flushWord()
		if len(words) > 0 {
			segs = append(segs, words)
			words = nil
		}
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch c {
		case '\'':
			inWord, quoted = true, true
			j := strings.IndexByte(cmd[i+1:], '\'')
			if j < 0 {
				cur.WriteString(cmd[i+1:])
				i = len(cmd)
			} else {
				cur.WriteString(cmd[i+1 : i+1+j])
				i += j + 1
			}
		case '"':
			inWord, quoted = true, true
			i++
			for i < len(cmd) && cmd[i] != '"' {
				if cmd[i] == '\\' && i+1 < len(cmd) {
					i++
				}
				cur.WriteByte(cmd[i])
				i++
			}
		case '\\':
			inWord, quoted = true, true
			if i+1 < len(cmd) {
				i++
				cur.WriteByte(cmd[i])
			}
		case ' ', '\t':
			flushWord()
		case ';', '&', '|', '\n', '(', ')', '`':
			flushSeg()
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	flushSeg()
	return segs
}

func collect(cmd string, depth int, add, arg func(string)) {
	for _, seg := range splitSegments(cmd) {
		words := make([]string, len(seg))
		for k, w := range seg {
			words[k] = w.s
		}
		i := 0
		for i < len(words) {
			w := words[i]
			switch {
			case assignRE.MatchString(w), keywords[w], w == "$":
				i++
			case wrappers[w]:
				i = skipWrapperArgs(words, i+1, w)
			default:
				goto program
			}
		}
		continue
	program:
		prog := path.Base(words[i])
		if prog == "" || prog == "." || prog == "/" || strings.HasPrefix(prog, "$") {
			continue
		}
		add(prog)
		// Weak names: standalone (unquoted) arguments after the program, so
		// exec-through wrappers (perl -e '...exec @ARGV' python3, xargs
		// python3) are visible without listing each wrapper.
		for _, w := range seg[i+1:] {
			if w.q || w.s == "" || strings.HasPrefix(w.s, "-") || strings.HasPrefix(w.s, "$") || assignRE.MatchString(w.s) {
				continue
			}
			arg(path.Base(w.s))
		}
		np := NormalizeName(prog)
		if !interpreters[np] {
			continue
		}
		rest := words[i+1:]
		for k := 0; k < len(rest); k++ {
			a := rest[k]
			switch {
			case a == "-m" && k+1 < len(rest):
				add(strings.SplitN(rest[k+1], ".", 2)[0])
				k = len(rest)
			case a == "-c" && shells[np] && k+1 < len(rest):
				if depth < maxProgDepth {
					collect(rest[k+1], depth+1, add, arg)
				}
				k = len(rest)
			case strings.HasPrefix(a, "-"):
				// another flag; its argument, if any, is not tracked
			default:
				base := path.Base(a)
				add(strings.TrimSuffix(base, path.Ext(base)))
				k = len(rest)
			}
		}
	}
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' && r != 's' && r != 'm' && r != 'h' {
			return false
		}
	}
	return true
}

// skipWrapperArgs skips a wrapper's flags, flag arguments, assignments and
// numeric arguments (timeout 30), returning the index of the wrapped program.
func skipWrapperArgs(words []string, i int, wrapper string) int {
	for i < len(words) {
		switch {
		case strings.HasPrefix(words[i], "-"):
			if argFlags[wrapper][words[i]] {
				i++
			}
			i++
		case assignRE.MatchString(words[i]) || isNumber(words[i]):
			i++
		default:
			return i
		}
	}
	return i
}

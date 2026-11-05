package alerts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modPrefix = "github.com/ericmacdougall/netwatch/"

// forbiddenImports can deliver a signal or hold the executor. internal/guard
// holds the Signaller and the executor.
var forbiddenImports = map[string]bool{
	"syscall":                     true,
	"os/exec":                     true,
	"os/signal":                   true,
	"golang.org/x/sys/unix":       true,
	modPrefix + "internal/guard":  true,
	modPrefix + "internal/execx":  true,
	modPrefix + "internal/jetsam": true,
}

// forbiddenCalls are selector names that signal a process.
var forbiddenCalls = map[string]bool{"Kill": true, "Killpg": true, "Tgkill": true, "Signal": true, "FindProcess": true}

// sigViolations parses every non-test Go file in dir and reports forbidden
// imports and calls. goFilesOnly keeps the check independent of build tags.
func sigViolations(t *testing.T, dir string, checkImports bool) (v []string, imports []string) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			imports = append(imports, p)
			if checkImports && forbiddenImports[p] {
				v = append(v, f+": imports "+p)
			}
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok && forbiddenCalls[s.Sel.Name] {
				v = append(v, f+": uses ."+s.Sel.Name)
			}
			return true
		})
	}
	return v, imports
}

// closure returns the module-internal packages reachable from dir.
func closure(t *testing.T, root, dir string) []string {
	seen := map[string]bool{}
	var walk func(d string)
	walk = func(d string) {
		if seen[d] {
			return
		}
		seen[d] = true
		_, imps := sigViolations(t, d, false)
		for _, p := range imps {
			if rest, ok := strings.CutPrefix(p, modPrefix); ok {
				walk(filepath.Join(root, rest))
			}
		}
	}
	walk(dir)
	var out []string
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// TestNoSignalCapability: the alerts package and every module package it
// depends on must not be able to signal a process: no signalling calls
// anywhere in the closure, and no path to the guard or executor packages.
func TestNoSignalCapability(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	self, _ := filepath.Abs(".")
	pkgs := closure(t, root, self)
	if len(pkgs) < 3 {
		t.Fatalf("closure looks wrong: %v", pkgs)
	}
	for _, d := range pkgs {
		v, imps := sigViolations(t, d, false)
		for _, p := range imps {
			switch {
			case d == self && forbiddenImports[p]:
				v = append(v, d+": imports "+p)
			case d != self && strings.HasPrefix(p, modPrefix) && forbiddenImports[p]:
				// A dependency that reaches the guard or executor packages.
				v = append(v, d+": imports "+p)
			}
		}
		if len(v) > 0 {
			t.Errorf("%s can signal: %v", d, v)
		}
	}
}

// The checker itself must catch a violation, or the test above is vacuous.
func TestNoSignalCheckerDetectsViolations(t *testing.T) {
	dir := t.TempDir()
	src := "package x\nimport (\n\t\"syscall\"\n\t\"os\"\n)\nfunc f(p *os.Process) { syscall.Kill(1, 9); p.Signal(os.Kill) }\n"
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	v, _ := sigViolations(t, dir, true)
	joined := strings.Join(v, "\n")
	for _, want := range []string{"imports syscall", "uses .Kill", "uses .Signal"} {
		if !strings.Contains(joined, want) {
			t.Errorf("checker missed %q in %v", want, v)
		}
	}
}

func TestAlertsImportsAreAllowlisted(t *testing.T) {
	self, _ := filepath.Abs(".")
	_, imps := sigViolations(t, self, false)
	allowed := map[string]bool{
		"fmt": true, "sort": true, "strings": true, "time": true,
		modPrefix + "internal/notify": true, modPrefix + "internal/record": true,
		modPrefix + "internal/resources": true, modPrefix + "internal/redact": true, // text only
	}
	for _, p := range imps {
		if !allowed[p] {
			t.Errorf("alerts imports %q; add it to the allowlist only if it cannot signal", p)
		}
	}
}

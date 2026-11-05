//go:build guardtest

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/safeio"
)

// guardtestBuild marks the live-test build. Release builds never carry the
// guardtest tag; scripts/build-release.sh checks that `guard simulate` is
// unknown to every binary it ships.
const guardtestBuild = true

// injection is <stateDir>/inject.json: a danger reading the test daemon
// substitutes for the real one, so a live test can drive the guard
// through pause and kill without making the host itself short of memory.
type injection struct {
	Pressure       string  `json:"pressure"`        // "", "normal", "warn", "critical"
	CompressorFrac float64 `json:"compressor_frac"` // 0 leaves the real reading
}

const injectFile = "inject.json"

// injectReader overrides System() with inject.json when the file exists.
// It wraps only the test daemon's loop reader; signal checks probe the
// real reader.
type injectReader struct {
	resources.Full
	path string
}

func (r injectReader) System() (resources.System, error) {
	s, err := r.Full.System()
	if err != nil {
		return s, err
	}
	var in injection
	if safeio.ReadJSON(r.path, safeio.Opts{Max: 4096, RequireOwner: true, MaxPerm: 0o600}, &in) != nil {
		return s, nil
	}
	switch in.Pressure {
	case "critical":
		s.Pressure = resources.LevelCritical
	case "warn":
		s.Pressure = resources.LevelWarn
	case "normal":
		s.Pressure = resources.LevelNormal
	}
	if in.CompressorFrac > 0 {
		s.PagesCompressedLimit = 1 << 20
		s.PagesCompressed = uint64(in.CompressorFrac * float64(s.PagesCompressedLimit))
	}
	return s, nil
}

// testReader is the test daemon's loop reader.
func testReader(r resources.Full, stateDir string) resources.Full {
	return injectReader{Full: r, path: filepath.Join(stateDir, injectFile)}
}

// guardSimulate writes or clears inject.json:
//
//	guard simulate critical [COMPRESSOR_FRAC] | warn | clear
func (a *app) guardSimulate(stateDir string, args []string) error {
	if len(args) == 0 || len(args) > 2 {
		return usageError{errors.New("guard simulate needs: critical [COMPRESSOR_FRAC] | warn | clear")}
	}
	in := injection{Pressure: args[0]}
	switch args[0] {
	case "clear":
		in.Pressure = "normal"
	case "critical", "warn":
	default:
		return usageError{fmt.Errorf("guard simulate: unknown level %q", args[0])}
	}
	if len(args) == 2 {
		f, err := strconv.ParseFloat(args[1], 64)
		if err != nil || f <= 0 || f > 1 {
			return usageError{fmt.Errorf("guard simulate: compressor fraction %q must be in (0,1]", args[1])}
		}
		in.CompressorFrac = f
	}
	data := []byte(fmt.Sprintf(`{"pressure":%q,"compressor_frac":%g}`, in.Pressure, in.CompressorFrac))
	if err := safeio.WriteFileAtomic(stateDir, injectFile, data); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "netwatch: test daemon reading set to %s\n", data)
	return nil
}

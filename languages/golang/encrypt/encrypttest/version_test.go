package encrypttest

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestTheTwoModulesMustBeAtOneVersion(t *testing.T) {
	module := func(path, version string) *debug.Module {
		return &debug.Module{Path: path, Version: version}
	}
	replaced := module(sdkModule, "v0.1.0")
	replaced.Replace = module("../..", "")
	byVersion := func(path, required, runs string) *debug.Module {
		m := module(path, required)
		m.Replace = module(path, runs)
		return m
	}
	for _, c := range []struct {
		name string
		deps []*debug.Module
		ok   bool
	}{
		{"the same version", []*debug.Module{module(sdkModule, "v0.1.0"), module(thisModule, "v0.1.0")}, true},
		{"different versions", []*debug.Module{module(sdkModule, "v0.2.0"), module(thisModule, "v0.1.0")}, false},
		{"a pseudo-version of this module", []*debug.Module{module(sdkModule, "v0.1.0"), module(thisModule, "v0.1.1-0.20261117000000-abcdef012345")}, false},
		{"the SDK replaced by a directory", []*debug.Module{replaced, module(thisModule, "v0.1.0")}, true},
		{"the SDK replaced by another version", []*debug.Module{byVersion(sdkModule, "v0.2.0", "v0.1.0"), module(thisModule, "v0.2.0")}, false},
		{"the SDK replaced by this module's version", []*debug.Module{byVersion(sdkModule, "v0.1.0", "v0.2.0"), module(thisModule, "v0.2.0")}, true},
		{"this module is the one being built", []*debug.Module{module(sdkModule, "v0.1.0")}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := sameVersion(&debug.BuildInfo{Main: debug.Module{Path: "example.com/app", Version: "(devel)"}, Deps: c.deps})
			if c.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "same version")) {
				t.Fatalf("accepted, or refused without saying why: %v", err)
			}
		})
	}
}

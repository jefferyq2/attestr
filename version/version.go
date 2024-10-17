package version

import (
	"fmt"
	"runtime/debug"

	"github.com/Masterminds/semver/v3"
)

const ThisModulePath = "github.com/docker/attest"

type Fetcher interface {
	Get() (*semver.Version, error)
}

type GoModVersionFetcher struct{}

func NewGoVersionFetcher() *GoModVersionFetcher {
	return &GoModVersionFetcher{}
}

// Get returns the version of the attest module.
// this can return nil if the version can't be determined (without an error).
func (*GoModVersionFetcher) Get() (*semver.Version, error) {
	var attestMod *debug.Module
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, nil
	}
	if bi.Main.Path == ThisModulePath {
		attestMod = &bi.Main
	} else {
		for _, dep := range bi.Deps {
			if dep.Path == ThisModulePath {
				attestMod = dep
				break
			}
		}
	}
	if attestMod == nil {
		return nil, nil
	}

	attestVersion, err := semver.NewVersion(attestMod.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version %s: %w", attestMod.Version, err)
	}
	return attestVersion, nil
}

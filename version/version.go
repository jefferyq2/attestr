/*
   Copyright 2024 Docker attest authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
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

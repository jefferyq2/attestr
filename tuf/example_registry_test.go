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
package tuf_test

import (
	"context"
	"os"
	"path/filepath"

	"github.com/docker/attest/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func ExampleNewClient_registry() {
	// create a tuf client
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	tufOutputPath := filepath.Join(home, ".docker", "tuf")

	opts := tuf.NewDockerDefaultClientOptions(tufOutputPath)
	registryClient, err := tuf.NewClient(context.Background(), opts)
	if err != nil {
		panic(err)
	}

	// get trusted tuf metadata
	trustedMetadata := registryClient.GetMetadata()

	// top-level target files
	targets := trustedMetadata.Targets[metadata.TARGETS].Signed.Targets

	for _, t := range targets {
		// download target files
		_, err := registryClient.DownloadTarget(t.Path, filepath.Join(tufOutputPath, "download"))
		if err != nil {
			panic(err)
		}
	}
}

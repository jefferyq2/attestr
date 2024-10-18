/*
   Copyright Docker attest authors

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

package mirror

import (
	"context"
	"fmt"

	"github.com/docker/attest/tuf"
)

func NewTUFMirror(ctx context.Context, root []byte, tufPath, metadataURL, targetsURL string, versionChecker tuf.VersionChecker) (*TUFMirror, error) {
	if root == nil {
		root = tuf.DockerTUFRootDefault.Data
	}
	tufClient, err := tuf.NewClient(ctx, &tuf.ClientOptions{InitialRoot: root, LocalStorageDir: tufPath, MetadataSource: metadataURL, TargetsSource: targetsURL, VersionChecker: versionChecker})
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}
	return &TUFMirror{TUFClient: tufClient, tufPath: tufPath, metadataURL: metadataURL, targetsURL: targetsURL}, nil
}

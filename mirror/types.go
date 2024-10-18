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
	"github.com/docker/attest/oci"
	"github.com/docker/attest/tuf"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	DefaultMetadataURL   = "https://docker.github.io/tuf/metadata"
	DefaultTargetsURL    = "https://docker.github.io/tuf/targets"
	tufMetadataMediaType = "application/vnd.tuf.metadata+json"
	tufTargetMediaType   = "application/vnd.tuf.target"
	tufFileAnnotation    = "tuf.io/filename"
)

type TUFRole string

var TUFRoles = []TUFRole{metadata.ROOT, metadata.SNAPSHOT, metadata.TARGETS, metadata.TIMESTAMP}

type TUFMetadata struct {
	Root      map[string][]byte
	Snapshot  map[string][]byte
	Targets   map[string][]byte
	Timestamp []byte
}

type DelegatedTargetMetadata struct {
	Name    string
	Version string
	Data    []byte
}

type Image struct {
	Image *oci.EmptyConfigImage
	Tag   string
}

type Index struct {
	Index v1.ImageIndex
	Tag   string
}

type TUFMirror struct {
	TUFClient   *tuf.Client
	tufPath     string
	metadataURL string
	targetsURL  string
}

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

package embed

import (
	_ "embed"
	"fmt"
)

//go:embed embedded-roots/1.root-dev.json
var devRoot []byte

//go:embed embedded-roots/1.root-staging.json
var stagingRoot []byte

//go:embed embedded-roots/1.root.json
var prodRoot []byte

var defaultRoot = prodRoot

type (
	RootName     string
	EmbeddedRoot struct {
		Data []byte
		Name RootName
	}
)

var (
	RootDev     = EmbeddedRoot{Data: devRoot, Name: "dev"}
	RootStaging = EmbeddedRoot{Data: stagingRoot, Name: "staging"}
	RootProd    = EmbeddedRoot{Data: prodRoot, Name: "prod"}
	RootDefault = EmbeddedRoot{Data: defaultRoot, Name: ""}
)

func GetRootFromName(root string) (*EmbeddedRoot, error) {
	switch root {
	case string(RootDev.Name):
		return &RootDev, nil
	case string(RootStaging.Name):
		return &RootStaging, nil
	case string(RootProd.Name):
		return &RootProd, nil
	case string(RootDefault.Name):
		return &RootDefault, nil
	default:
		return nil, fmt.Errorf("invalid tuf root: %s", root)
	}
}

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

package tuf

import (
	"io"
	"os"
	"path/filepath"

	"github.com/docker/attest/internal/util"
)

type MockTufClient struct {
	srcPath string
}

func NewMockTufClient(srcPath string) *MockTufClient {
	if srcPath == "" {
		panic("srcPath must be set")
	}
	return &MockTufClient{
		srcPath: srcPath,
	}
}

func (dc *MockTufClient) DownloadTarget(target string, _ string) (file *TargetFile, err error) {
	targetPath := filepath.Join(dc.srcPath, target)
	src, err := os.Open(targetPath)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	b, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}

	return &TargetFile{TargetURI: targetPath, Data: b, Digest: util.SHA256Hex(b)}, nil
}

type MockVersionChecker struct {
	err error
}

func NewMockVersionChecker() *MockVersionChecker {
	return &MockVersionChecker{}
}

func (vc *MockVersionChecker) CheckVersion(_ Downloader) error {
	return vc.err
}

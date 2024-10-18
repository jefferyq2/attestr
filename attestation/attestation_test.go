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

package attestation_test

import (
	"testing"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/test"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
)

const ExpectedStatements = 4

func TestExtractAnnotatedStatements(t *testing.T) {
	statements, err := attestation.ExtractAnnotatedStatements(test.UnsignedTestIndex(".."), intoto.PayloadType)
	assert.NoError(t, err)
	assert.Equalf(t, len(statements), ExpectedStatements, "expected %d statement, got %d", ExpectedStatements, len(statements))
}

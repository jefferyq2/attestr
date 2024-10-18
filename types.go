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

package attest

import (
	"context"
	"fmt"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/policy"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

type Outcome string

const (
	OutcomeSuccess  Outcome = "success"
	OutcomeFailure  Outcome = "failure"
	OutcomeNoPolicy Outcome = "no_policy"
)

func (o Outcome) StringForVSA() (string, error) {
	switch o {
	case OutcomeSuccess:
		return "PASSED", nil
	case OutcomeFailure:
		return "FAILED", nil
	default:
		return "", fmt.Errorf("unknown outcome: %s", o)
	}
}

type VerificationResult struct {
	Outcome           Outcome
	Policy            *policy.Policy
	Input             *policy.Input
	VSA               *intoto.Statement
	Violations        []policy.Violation
	SubjectDescriptor *v1.Descriptor
}

type wrappedResolver struct {
	imageName string
	attestation.Resolver
}

func (w *wrappedResolver) ImageName(_ context.Context) (string, error) {
	return w.imageName, nil
}

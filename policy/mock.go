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
package policy

import (
	"context"

	"github.com/docker/attest/attestation"
)

type MockPolicyEvaluator struct {
	EvaluateFunc func(ctx context.Context, resolver attestation.Resolver, pctx *Policy, input *Input) (*Result, error)
}

func (pe *MockPolicyEvaluator) Evaluate(ctx context.Context, resolver attestation.Resolver, pctx *Policy, input *Input) (*Result, error) {
	if pe.EvaluateFunc != nil {
		return pe.EvaluateFunc(ctx, resolver, pctx, input)
	}
	return AllowedResult(), nil
}

func GetMockPolicy() Evaluator {
	return &MockPolicyEvaluator{
		EvaluateFunc: func(_ context.Context, _ attestation.Resolver, _ *Policy, _ *Input) (*Result, error) {
			return AllowedResult(), nil
		},
	}
}

func AllowedResult() *Result {
	return &Result{
		Success: true,
	}
}

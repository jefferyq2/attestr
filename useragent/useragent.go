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
package useragent

import (
	"context"

	"github.com/docker/attest/version"
)

type userAgentKeyType string

const (
	userAgentKey     userAgentKeyType = "attest-user-agent"
	defaultUserAgent string           = "attest/unknown (docker)"
)

func Set(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, userAgentKey, userAgent)
}

// Get retrieves the HTTP user agent from the context.
func Get(ctx context.Context) string {
	fetcher := version.NewGoVersionFetcher()
	if ua, ok := ctx.Value(userAgentKey).(string); ok {
		return ua
	}
	version, err := fetcher.Get()
	if err != nil || version == nil {
		return defaultUserAgent
	}

	return "attest/" + version.String() + " (docker)"
}

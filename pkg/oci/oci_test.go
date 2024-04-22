package oci

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRefToPurl(t *testing.T) {
	purl, canonical, err := RefToPURL("alpine", "arm64/linux")
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@latest?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("alpine:123", "arm64/linux")
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("google/alpine:123", "arm64/linux")
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/google/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("library/alpine:123", "arm64/linux")
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("docker.io/library/alpine:123", "arm64/linux")
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("localhost:5001/library/alpine:123", "arm64/linux")
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/localhost%3A5001/library/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("localhost:5001/alpine:123", "arm64/linux")
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/localhost%3A5001/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("localhost:5001/alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b", "arm64/linux")
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/localhost%3A5001/alpine?digest=sha256%3Ac5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b&platform=arm64%2Flinux", purl)
	assert.True(t, canonical)
}

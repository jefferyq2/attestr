#!/bin/bash
set -eo pipefail

echo "Starting the process to generate testdata..."

# Define functions
function check_command () {
    command -v "$1" >/dev/null 2>&1 || { echo >&2 "This script requires $1 but it's not installed.  Aborting."; exit 1; }
}

function cleanup_testdata () {
    echo "Cleaning up existing testdata..."
    rm -rf "${TESTDATA_PATH:?}/${UNSIGNED_IMAGE_DIR:?}"
    rm -rf "${TESTDATA_PATH:?}/${NO_PROVENANCE_IMAGE_DIR:?}"
}

function build_unsigned_image () {
    echo "Building $UNSIGNED_IMAGE_DIR..."
    docker buildx build "$TEST_IMAGE_DOCKERFILE_PATH" --sbom true --provenance true --platform linux/amd64,linux/arm64 \
      --output type=oci,tar=false,name="$TEST_IMAGE_REPO:$TEST_IMAGE_TAG",dest="$TESTDATA_PATH/$UNSIGNED_IMAGE_DIR"
}

function build_no_provenance_image () {
    echo "Building unsigned $NO_PROVENANCE_IMAGE_DIR..."
    docker buildx build "$TEST_IMAGE_DOCKERFILE_PATH" --sbom true --provenance false --platform linux/amd64,linux/arm64 \
      --output type=oci,tar=false,name="$TEST_IMAGE_REPO:$TEST_IMAGE_TAG",dest="$TESTDATA_PATH/$NO_PROVENANCE_IMAGE_DIR"
}

# Check required commands
check_command docker

TESTDATA_PATH="../test/testdata"
TEST_IMAGE_DOCKERFILE_PATH="../test"
TEST_IMAGE_REPO="test-image"
TEST_IMAGE_TAG="test"
UNSIGNED_IMAGE_DIR="unsigned-test-image"
NO_PROVENANCE_IMAGE_DIR="no-provenance-image"
ATTESTATION_PAYLOADTYPE="application/vnd.in-toto+json"

# Run steps
cleanup_testdata
build_unsigned_image
build_no_provenance_image

echo "Process completed successfully."

# attest
Library to create, verify, and evaluate policy for attestations on container images

# usage
## signing attestations


## verifying attestations
1. Create a TUF client
    * using OCI registry for TUF
        ```go
        tufClient, err := tuf.NewTufClient(embed.DefaultRoot, "/.docker/tuf", "docker/tuf-metadata:latest", "docker/tuf-targets")
        ```
    * using HTTPS for TUF
        ```go
        tufClient, err := tuf.NewTufClient(embed.DefaultRoot, "/.docker/tuf", "https://docker.github.io/tuf/metadata", "https://docker.github.io/tuf/targets")
        ```

1. Configure an attestation resolver
    * using OCI registry
        ```go
        var resolver oci.AttestationResolver
        resolver = &oci.RegistryResolver{
			Image:    image,    // path to image index in OCI registry containing image attestations (e.g. docker/nginx:latest)
			Platform: platform, // platform of subject image (image that attestations are being verified against)
		}
        ```
    * using local OCI layout
        ```go
        var resolver oci.AttestationResolver
        resolver = &oci.OCILayoutResolver{
			Path:     path,     // file path to OCI layout containing image attestations (e.g. /myimage)
			Platform: platform, // platform of subject image (image that attestations are being verified against)
		}
        ```

2. Configure policy options
    ```go
    opts := &policy.PolicyOptions{
		TufClient:       tufClient,
		LocalTargetsDir: "/.docker/policy", // location to store policy files downloaded from TUF
		LocalPolicyDir:  "", // overrides TUF policy for local policy files
	}
    ```

3. Verify attestations
    ```go
    policy, err := attest.Verify(ctx, opts, resolver)
    if err != nil {
        return false // failed policy or attestation signature verification
    }
    if policy {
        return true // passed policy
    }
    return true // no policy for image
    ```

## mirroring TUF repositories
TODO: write content for this outline
### mirroring TUF metadata to OCI
#### delegated metadata
### mirroring TUF targets to OCI
#### delegated targets
### using `go-tuf` OCI registry client

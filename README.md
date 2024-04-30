# attest
library to create, verify, and evaluate policy for attestations on container images

# usage
## signing attestations
1. generate an image with intoto Statements (optional)
   ```sh
   docker buildx build <PATH TO DOCKERFILE> --sbom true --provenance true --output type=oci,tar=false,name=<REPO>:<TAG>,dest=<OUTPUT DIR>
   ```

1. confgiure a `dsse.SignerVerifier`
   ```go
   var signer dsse.SignerVerifier 
   signer, err = signerverifier.GetAWSSigner(cmd.Context(), aws_arn, aws_region)
   ```

1. configure signing options
   ```go
   opts := &attest.SigningOptions{
		Replace: true, // replace unsigned intoto statements with signed intoto attestations, otherwise leave in place
        }
   ```
   * add [Verification Summary Attestation (VSA)](https://slsa.dev/spec/v1.0/verification_summary) for all intoto attestations (optional)
        ```go
        opts.VSAOptions = &attestation.VSAOptions{
			BuildLevel: "SLSA_BUILD_LEVEL_" + slsaBuildLevel,
			PolicyURI:  slsaPolicyUri,
			VerifierID: slsaVerifierId,
            }
        ```
1. load attestations 
   * oci registry
        ```go
        ref := "docker/attest:latest"
        att, err := oci.AttestationIndexFromRemote(ref)
        ```
   * local filepath
        ```go
        path := "/test-image"
        att, err := oci.AttestationIndexFromPath(path)
        ```

1. sign attestations
    ```go
    signedImageIndex, err := attest.Sign(ctx, att, signer, opts)
    ```
    `attest.Sign()` iterates over attestation manifests in the image index and signs all intoto statements (optionally generates a VSA), returning a mutated ImageIndex with all intoto statements signed as attestations.

1. save output (optional)
    * push to oci registry
        ```go
        err = mirror.PushToRegistry(signedImageIndex, ref)
        ```
    * save to local filesystem
        ```go
        idx := v1.ImageIndex(empty.Index)
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add: signedImageIndex,
			Descriptor: v1.Descriptor{
				Annotations: map[string]string{
					oci.OciReferenceTarget: att.Name,
				},
			},
		})
		err = mirror.SaveAsOCILayout(idx, path)
        ```

## verifying attestations
1. create a TUF client
    * using OCI registry for TUF
        ```go
        tufClient, err := tuf.NewTufClient(embed.DefaultRoot, "/.docker/tuf", "docker/tuf-metadata:latest", "docker/tuf-targets")
        ```
    * using HTTPS for TUF
        ```go
        tufClient, err := tuf.NewTufClient(embed.DefaultRoot, "/.docker/tuf", "https://docker.github.io/tuf/metadata", "https://docker.github.io/tuf/targets")
        ```

1. configure an attestation resolver
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

1. configure policy options
    ```go
    opts := &policy.PolicyOptions{
		TufClient:       tufClient,
		LocalTargetsDir: "/.docker/policy", // location to store policy files downloaded from TUF
		LocalPolicyDir:  "", // overrides TUF policy for local policy files
	}
    ```

1. verify attestations
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

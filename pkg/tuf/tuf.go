package tuf

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/attest/internal/embed"
	"github.com/docker/attest/internal/util"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

type Source string

const (
	HTTPSource Source = "http"
	OCISource  Source = "oci"
	LatestTag  string = "latest"
)

var (
	DockerTUFRootProd    = embed.RootProd
	DockerTUFRootStaging = embed.RootStaging
	DockerTUFRootDev     = embed.RootDev
	DockerTUFRootDefault = embed.RootDefault
)

type Downloader interface {
	DownloadTarget(target, filePath string) (file *TargetFile, err error)
}

type Client struct {
	updater *updater.Updater
	cfg     *config.UpdaterConfig
}

type TargetFile struct {
	ActualFilePath string
	TargetURI      string
	Digest         string
	Data           []byte
}

// NewClient creates a new TUF client.
func NewClient(initialRoot []byte, tufPath, metadataSource, targetsSource string, versionChecker VersionChecker) (*Client, error) {
	var tufSource Source
	if strings.HasPrefix(metadataSource, "https://") || strings.HasPrefix(metadataSource, "http://") {
		tufSource = HTTPSource
	} else {
		tufSource = OCISource
	}

	tufRootDigest := util.SHA256Hex(initialRoot)

	// create a directory for each initial root.json
	metadataPath := filepath.Join(tufPath, tufRootDigest)
	err := os.MkdirAll(metadataPath, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to create directory '%s': %w", metadataPath, err)
	}
	rootFile := filepath.Join(metadataPath, "root.json")
	var rootBytes []byte
	rootBytes, err = os.ReadFile(rootFile)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("failed to read root.json: %w", err)
		}
		// write the root.json file to the metadata directory
		err = os.WriteFile(rootFile, initialRoot, 0o666) // #nosec G306
		if err != nil {
			return nil, fmt.Errorf("Failed to write root.json %w", err)
		}
		rootBytes = initialRoot
	}

	// create updater configuration
	cfg, err := config.New(metadataSource, rootBytes) // default config
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF updater configuration: %w", err)
	}
	cfg.LocalMetadataDir = metadataPath
	cfg.LocalTargetsDir = filepath.Join(metadataPath, "download")
	cfg.RemoteTargetsURL = targetsSource

	if tufSource == OCISource {
		metadataRepo, metadataTag, found := strings.Cut(metadataSource, ":")
		if !found {
			fmt.Printf("metadata tag not found in URL, using latest\n")
			metadataTag = LatestTag
		}
		cfg.Fetcher = NewRegistryFetcher(metadataRepo, metadataTag, targetsSource)
	}

	// create a new Updater instance
	up, err := updater.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF updater instance: %w", err)
	}

	// try to build the top-level metadata
	err = up.Refresh()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh trusted metadata: %w", err)
	}

	client := &Client{
		updater: up,
		cfg:     cfg,
	}

	err = versionChecker.CheckVersion(client)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (t *Client) generateTargetURI(target *metadata.TargetFiles, digest string) (string, error) {
	targetBaseURL := ensureTrailingSlash(t.cfg.RemoteTargetsURL)
	targetRemotePath := target.Path
	if t.cfg.PrefixTargetsWithHash {
		baseName := filepath.Base(targetRemotePath)
		dirName, ok := strings.CutSuffix(targetRemotePath, "/"+baseName)
		if !ok {
			// <hash>.<target-name>
			targetRemotePath = fmt.Sprintf("%s.%s", digest, baseName)
		} else {
			// <dir-prefix>/<hash>.<target-name>
			targetRemotePath = fmt.Sprintf("%s/%s.%s", dirName, digest, baseName)
		}
	}
	fullURL := fmt.Sprintf("%s%s", targetBaseURL, targetRemotePath)

	switch fetcher := t.cfg.Fetcher.(type) {
	case *RegistryFetcher:
		return fmt.Sprintf("%s@sha256:%s", t.cfg.RemoteTargetsURL, digest), nil
	case *fetcher.DefaultFetcher:
		return fullURL, nil
	default:
		return "", fmt.Errorf("unsupported fetcher type: %T", fetcher)
	}
}

// DownloadTarget downloads the target file using Updater. The Updater gets the target
// information, verifies if the target is already cached, and if it is not cached,
// downloads the target file.
func (t *Client) DownloadTarget(target string, filePath string) (file *TargetFile, err error) {
	// search if the desired target is available
	targetInfo, err := t.updater.GetTargetInfo(target)
	if err != nil {
		return nil, err
	}

	// check if filePath exists and create the directory if it doesn't
	if _, err := os.Stat(filepath.Dir(filePath)); os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Dir(filePath), os.ModePerm)
		if err != nil {
			return nil, fmt.Errorf("failed to create target download directory '%s': %w", filepath.Dir(filePath), err)
		}
	}

	// target is available, so let's see if the target is already present locally
	actualFilePath, data, err := t.updater.FindCachedTarget(targetInfo, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed while finding a cached target: %w", err)
	}
	if data != nil {
		digest := util.SHA256Hex(data)
		uri, err := t.generateTargetURI(targetInfo, digest)
		return &TargetFile{ActualFilePath: actualFilePath, TargetURI: uri, Data: data, Digest: digest}, err
	}

	// target is not present locally, so let's try to download it
	actualFilePath, data, err = t.updater.DownloadTarget(targetInfo, filePath, "")
	if err != nil {
		return nil, fmt.Errorf("failed to download target file %s - %w", target, err)
	}
	digest := util.SHA256Hex(data)
	uri, err := t.generateTargetURI(targetInfo, digest)
	return &TargetFile{ActualFilePath: actualFilePath, TargetURI: uri, Data: data, Digest: digest}, err
}

func (t *Client) GetMetadata() trustedmetadata.TrustedMetadata {
	return t.updater.GetTrustedMetadataSet()
}

func (t *Client) MaxRootLength() int64 {
	return t.cfg.RootMaxLength
}

func (t *Client) GetPriorRoots(metadataURL string) (map[string][]byte, error) {
	rootMetadata := map[string][]byte{}
	trustedMetadata := t.GetMetadata()
	client := fetcher.DefaultFetcher{}
	for i := 1; i < int(trustedMetadata.Root.Signed.Version); i++ {
		meta, err := client.DownloadFile(metadataURL+fmt.Sprintf("/%d.root.json", i), t.MaxRootLength(), time.Second*15)
		if err != nil {
			return nil, fmt.Errorf("failed to download root metadata: %w", err)
		}
		rootMetadata[fmt.Sprintf("%d.root.json", i)] = meta
	}
	return rootMetadata, nil
}

func (t *Client) SetRemoteTargetsURL(url string) {
	t.cfg.RemoteTargetsURL = url
}

// Derived from updater.loadTargets() in theupdateframework/go-tuf.
func (t *Client) LoadDelegatedTargets(roleName, parentName string) (*metadata.Metadata[metadata.TargetsType], error) {
	// extract the targets meta from the trusted snapshot metadata
	meta := t.updater.GetTrustedMetadataSet()
	metaInfo := meta.Snapshot.Signed.Meta[fmt.Sprintf("%s.json", roleName)]
	// extract the length of the target metadata to be downloaded
	length := metaInfo.Length
	if length == 0 {
		length = t.cfg.TargetsMaxLength
	}
	// extract which target metadata version should be downloaded in case of consistent snapshots
	version := ""
	if meta.Root.Signed.ConsistentSnapshot {
		version = strconv.FormatInt(metaInfo.Version, 10)
	}
	// download targets metadata
	data, err := t.downloadMetadata(roleName, length, version)
	if err != nil {
		return nil, err
	}
	// verify and load the new target metadata
	delegatedTargets, err := meta.UpdateDelegatedTargets(data, roleName, parentName)
	if err != nil {
		return nil, err
	}
	return delegatedTargets, nil
}

// downloadMetadata download a metadata file and return it as bytes.
func (t *Client) downloadMetadata(roleName string, length int64, version string) ([]byte, error) {
	urlPath := ensureTrailingSlash(t.cfg.RemoteMetadataURL)
	// build urlPath
	if version == "" {
		urlPath = fmt.Sprintf("%s%s.json", urlPath, url.QueryEscape(roleName))
	} else {
		urlPath = fmt.Sprintf("%s%s.%s.json", urlPath, version, url.QueryEscape(roleName))
	}
	return t.cfg.Fetcher.DownloadFile(urlPath, length, time.Second*15)
}

// ensureTrailingSlash ensures url ends with a slash.
func ensureTrailingSlash(url string) string {
	if updater.IsWindowsPath(url) {
		slash := string(filepath.Separator)
		if strings.HasSuffix(url, slash) {
			return url
		}
		return url + slash
	}
	if strings.HasSuffix(url, "/") {
		return url
	}
	return url + "/"
}

// GetEmbeddedRoot returns the embedded TUF root based on the given root name.
func GetEmbeddedRoot(root string) (*embed.EmbeddedRoot, error) {
	return embed.GetRootFromName(root)
}

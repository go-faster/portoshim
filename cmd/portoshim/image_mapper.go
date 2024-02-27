package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd/remotes/docker/auth"
	"github.com/distribution/reference"
	"github.com/ten-nancy/porto/src/api/go/porto"
	pb "github.com/ten-nancy/porto/src/api/go/porto/pkg/rpc"
	v1 "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type PortoshimImageMapper struct{}

// INTERNAL
func parseImageName(name string) (string, string, string) {
	image, digest, _ := strings.Cut(name, "@")
	image, tag, tagFound := strings.Cut(image, ":")
	if !tagFound {
		tag = "latest"
	}

	return image, tag, digest
}

func getImageStruct(image *pb.TDockerImage) *v1.Image {
	return &v1.Image{
		Id:          image.GetId(),
		RepoTags:    image.GetTags(),
		RepoDigests: image.GetDigests(),
		Size_:       image.GetSize(),
		Uid: &v1.Int64Value{
			Value: 1,
		},
		Username: "",
		Spec:     nil,
	}
}

// IMAGE SERVICE INTERFACE
func (m *PortoshimImageMapper) ListImages(ctx context.Context, req *v1.ListImagesRequest) (*v1.ListImagesResponse, error) {
	pc := getPortoClient(ctx)

	portoImages, err := pc.ListDockerImages("", "")
	if err != nil {
		return nil, fmt.Errorf("%s: %v", getCurrentFuncName(), err)
	}

	var images []*v1.Image
	for _, image := range portoImages {
		images = append(images, getImageStruct(image))
	}

	return &v1.ListImagesResponse{
		Images: images,
	}, nil
}

func (m *PortoshimImageMapper) ImageStatus(ctx context.Context, req *v1.ImageStatusRequest) (*v1.ImageStatusResponse, error) {
	pc := getPortoClient(ctx)

	image, err := pc.DockerImageStatus(req.GetImage().GetImage(), "")
	if err != nil {
		if err.(*porto.PortoError).Code == pb.EError_DockerImageNotFound {
			return &v1.ImageStatusResponse{
				Image: nil,
				Info:  map[string]string{},
			}, nil
		}
		return nil, fmt.Errorf("%s: %v", getCurrentFuncName(), err)
	}

	return &v1.ImageStatusResponse{
		Image: getImageStruct(image),
	}, nil
}

func (m *PortoshimImageMapper) PullImage(ctx context.Context, req *v1.PullImageRequest) (*v1.PullImageResponse, error) {
	pc := getPortoClient(ctx)

	image, err := pullImage(ctx, pc, req.GetImage().GetImage(), req.GetAuth())
	if err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}

	return &v1.PullImageResponse{
		ImageRef: image.GetId(),
	}, nil
}

func pullImage(ctx context.Context, pc porto.PortoAPI, img string, auth *v1.AuthConfig) (*pb.TDockerImage, error) {
	registry := GetImageRegistry(img)
	authToken := registry.AuthToken
	if authToken == "" {
		if auth != nil && auth.GetPassword() != "" {
			authToken = auth.GetPassword()
		} else {
			var err error
			authToken, err = fetchToken(ctx, img)
			if err != nil {
				DebugLog(ctx, "Fetch token failed: %v", err)
			}
		}
	}

	image, err := pc.PullDockerImage(img, "", authToken, registry.AuthPath, registry.AuthService)
	if err != nil {
		return nil, fmt.Errorf("request porto to pull %q: %w", img, err)
	}
	return image, nil
}

func fetchToken(ctx context.Context, img string) (string, error) {
	client := http.DefaultClient

	ref, err := reference.ParseNormalizedNamed(img)
	if err != nil {
		return "", fmt.Errorf("parse reference %q: %w", img, err)
	}
	var digestOrTag string
	switch ref := ref.(type) {
	case reference.Digested:
		digestOrTag = ref.Digest().String()
	case reference.Tagged:
		digestOrTag = ref.Tag()
	default:
		return "", nil
	}

	var authCfg AuthConfig
	for prefix, cfg := range Cfg.Images.AuthCfg.Auths {
		if !strings.HasPrefix(img, prefix) {
			continue
		}
		DebugLog(ctx, "Using auth config %q for %q", prefix, img)
		authCfg = cfg
		break
	}
	// Prefer defined registry token.
	if t := authCfg.RegistryToken; t != "" {
		return "Bearer " + t, nil
	}
	var (
		username = authCfg.Username
		secret   = authCfg.IdentityToken
		headers  http.Header
	)
	if secret == "" {
		secret = authCfg.Password
	}
	if h := Cfg.Images.AuthCfg.HTTPHeaders; len(h) > 0 {
		headers = http.Header{}
		for name, value := range h {
			headers.Set(name, value)
		}
	}

	manifestURL := (&url.URL{
		Scheme: "https",
		Host:   reference.Domain(ref),
	}).JoinPath(
		"v2",
		reference.Path(ref),
		"manifests",
		digestOrTag,
	).String()

	DebugLog(ctx, "Trying to fetch manifest %s", manifestURL)
	resp, err := get(ctx, client, manifestURL)
	if err != nil {
		return "", fmt.Errorf("get manifest: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	DebugLog(ctx, "Manifest %s fetch result: %d", manifestURL, resp.StatusCode)
	switch code := resp.StatusCode; {
	case code < 300:
		return "", nil
	case code == 401 || code == 403:
	default:
		return "", nil
	}

	for _, h := range auth.ParseAuthHeader(resp.Header) {
		if h.Scheme != auth.BearerAuth {
			DebugLog(ctx, "Skipping auth scheme %q", h.Scheme)
			continue
		}

		var (
			realm   = h.Parameters["realm"]
			service = h.Parameters["service"]
			scopes  []string
		)
		if scope, ok := h.Parameters["scope"]; ok {
			scopes = strings.Split(scope, " ")
		}

		resp, err := auth.FetchToken(ctx, client, headers, auth.TokenOptions{
			Realm:    realm,
			Service:  service,
			Scopes:   scopes,
			Username: username,
			Secret:   secret,
		})
		if err != nil {
			DebugLog(ctx, "Fetch token failed: %s", err)
			continue
		}
		DebugLog(ctx, "Got token (service: %q, realm: %q, scopes %#v)", service, realm, scopes)
		return "Bearer " + resp.Token, nil
	}

	return "", nil
}

func get(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	return resp, nil
}

func (m *PortoshimImageMapper) RemoveImage(ctx context.Context, req *v1.RemoveImageRequest) (*v1.RemoveImageResponse, error) {
	pc := getPortoClient(ctx)

	err := pc.RemoveDockerImage(req.GetImage().GetImage(), "")
	if err != nil {
		return nil, fmt.Errorf("%s: %v", getCurrentFuncName(), err)
	}

	return &v1.RemoveImageResponse{}, nil
}

func (m *PortoshimImageMapper) ImageFsInfo(ctx context.Context, req *v1.ImageFsInfoRequest) (*v1.ImageFsInfoResponse, error) {
	stat := syscall.Statfs_t{}
	err := syscall.Statfs(Cfg.Porto.ImagesDir, &stat)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", getCurrentFuncName(), err)
	}

	return &v1.ImageFsInfoResponse{
		ImageFilesystems: []*v1.FilesystemUsage{
			{
				Timestamp: time.Now().UnixNano(),
				FsId: &v1.FilesystemIdentifier{
					Mountpoint: Cfg.Porto.ImagesDir,
				},
				UsedBytes:  &v1.UInt64Value{Value: (stat.Blocks - stat.Bfree) * uint64(stat.Bsize)},
				InodesUsed: &v1.UInt64Value{Value: stat.Files - stat.Ffree},
			},
		},
	}, nil
}

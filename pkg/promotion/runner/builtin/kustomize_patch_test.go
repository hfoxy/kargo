package builtin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/resid"

	kargoapi "github.com/akuity/kargo/api/v1alpha1"
	"github.com/akuity/kargo/pkg/promotion"
	"github.com/akuity/kargo/pkg/x/promotion/runner/builtin"
)

func Test_kustomizePatch_convert(t *testing.T) {
	tests := []validationTestCase{
		{
			name:   "path is not specified",
			config: promotion.Config{},
			expectedProblems: []string{
				"(root): path is required",
			},
		},
		{
			name: "path is empty",
			config: promotion.Config{
				"path": "",
			},
			expectedProblems: []string{
				"path: String length must be greater than or equal to 1",
			},
		},
		{
			name: "image is not specified",
			config: promotion.Config{
				"path":          "fake-path",
				"kind":          "Deployment",
				"labelSelector": "app=demo",
				"pathToImage":   "/spec/template/spec/containers/0/image",
			},
			expectedProblems: []string{
				"(root): image is required",
			},
		},
		{
			name: "image name is empty",
			config: promotion.Config{
				"path":          "fake-path",
				"kind":          "Deployment",
				"labelSelector": "app=demo",
				"pathToImage":   "/spec/template/spec/containers/0/image",
				"image": promotion.Config{
					"image": "",
					"tag":   "v1",
				},
			},
			expectedProblems: []string{
				"image.image: String length must be greater than or equal to 1",
			},
		},
		{
			name: "path to image and split paths are mutually exclusive",
			config: promotion.Config{
				"path":             "fake-path",
				"kind":             "Deployment",
				"labelSelector":    "app=demo",
				"pathToImage":      "/image",
				"pathToRepository": "/repository",
				"pathToTag":        "/tag",
				"image": promotion.Config{
					"image": "fake-image",
					"tag":   "v1",
				},
			},
			expectedProblems: []string{
				"(root): Must validate one and only one schema (oneOf)",
			},
		},
		{
			name: "valid full image path config",
			config: promotion.Config{
				"path":          "fake-path",
				"kind":          "Deployment",
				"labelSelector": "app=demo",
				"pathToImage":   "/spec/template/spec/containers/0/image",
				"image": promotion.Config{
					"image":   "fake-image",
					"newName": "ghcr.io/example/demo",
					"tag":     "v1",
				},
			},
		},
		{
			name: "valid split image path config",
			config: promotion.Config{
				"path":             "fake-path",
				"kind":             "Deployment",
				"labelSelector":    "app=demo",
				"pathToRepository": "/spec/template/spec/containers/0/image",
				"pathToTag":        "/spec/template/spec/containers/0/tag",
				"image": promotion.Config{
					"image": "fake-image",
					"tag":   "v1",
				},
			},
		},
	}

	r := newKustomizePatch(promotion.StepRunnerCapabilities{})
	runner, ok := r.(*kustomizePatch)
	require.True(t, ok)

	runValidationTests(t, runner.convert, tests)
}

func Test_kustomizePatch_run(t *testing.T) {
	workDir := t.TempDir()
	kustomization := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
patches:
- target:
    kind: Deployment
    labelSelector: app=other
  patch: |-
    - op: replace
      path: /spec/template/spec/containers/0/image
      value: old/other:v1
- target:
    kind: Deployment
    labelSelector: app=demo
  patch: |-
    - op: replace
      path: /spec/template/spec/containers/0/image
      value: old/demo:v1
    - op: replace
      path: /spec/replicas
      value: "2"
`
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "kustomization.yaml"), []byte(kustomization), 0o600))

	runner := &kustomizePatch{}
	result, err := runner.run(t.Context(), &promotion.StepContext{WorkDir: workDir}, builtin.KustomizePatchConfig{
		Path:          ".",
		Kind:          "Deployment",
		LabelSelector: "app=demo",
		PathToImage:   "/spec/template/spec/containers/0/image",
		Image: builtin.KustomizePatchImage{
			Image:   "old/demo",
			NewName: "ghcr.io/example/demo",
			Tag:     "v2",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, kargoapi.PromotionStepStatusSucceeded, result.Status)
	assert.Equal(t, map[string]any{
		"commitMessage": "Updated . to use new image\n\n- ghcr.io/example/demo:v2",
	}, result.Output)

	updated, err := os.ReadFile(filepath.Join(workDir, "kustomization.yaml"))
	require.NoError(t, err)

	var kustomizationDoc struct {
		Patches []types.Patch `yaml:"patches"`
	}
	require.NoError(t, yaml.Unmarshal(updated, &kustomizationDoc))
	require.Len(t, kustomizationDoc.Patches, 2)
	assert.Equal(t, "app=other", kustomizationDoc.Patches[0].Target.LabelSelector)
	assert.Equal(t, "app=demo", kustomizationDoc.Patches[1].Target.LabelSelector)

	var patchOps []patchStringValue
	require.NoError(t, yaml.Unmarshal([]byte(kustomizationDoc.Patches[1].Patch), &patchOps))
	assert.Equal(t, []patchStringValue{
		{Op: "replace", Path: "/spec/replicas", Value: "2"},
		{Op: "replace", Path: "/spec/template/spec/containers/0/image", Value: "ghcr.io/example/demo:v2"},
	}, patchOps)
}

func Test_kustomizePatch_addPatches(t *testing.T) {
	runner := &kustomizePatch{}
	_, _, err := runner.addPatches(
		t.Context(),
		&promotion.StepContext{},
		builtin.KustomizePatchConfig{
			Kind:          "Deployment",
			LabelSelector: "app=demo",
			PathToImage:   "/image",
			Image: builtin.KustomizePatchImage{
				Image: "repo/demo",
				Tag:   "v2",
			},
		},
		[]types.Patch{
			{Target: &types.Selector{ResId: resid.NewResIdKindOnly("Deployment", ""), LabelSelector: "app=demo"}},
			{Target: &types.Selector{ResId: resid.NewResIdKindOnly("Deployment", ""), LabelSelector: "app=demo"}},
		},
	)
	require.ErrorContains(t, err, "multiple patches (2) matching criteria were found")
}

func Test_updatePatchOps(t *testing.T) {
	tests := []struct {
		name        string
		patch       string
		cfg         builtin.KustomizePatchConfig
		targetImage types.Image
		assertions  func(*testing.T, string, error)
	}{
		{
			name: "replaces full image path only",
			patch: `- op: replace
  path: /image
  value: old:v1
- op: replace
  path: /replicas
  value: "2"
`,
			cfg: builtin.KustomizePatchConfig{
				PathToImage: "/image",
				Image:       builtin.KustomizePatchImage{},
			},
			targetImage: types.Image{Name: "repo/demo", NewTag: "v2"},
			assertions: func(t *testing.T, patch string, err error) {
				require.NoError(t, err)
				assert.Contains(t, patch, "value: repo/demo:v2")
				assert.Contains(t, patch, "path: /replicas")
				assert.Equal(t, 1, strings.Count(patch, "path: /image"))
			},
		},
		{
			name: "replaces split repository and tag paths only",
			patch: `- op: replace
  path: /repository
  value: old
- op: replace
  path: /tag
  value: v1
- op: add
  path: /tag
  value: keep-me
`,
			cfg: builtin.KustomizePatchConfig{
				PathToRepository: "/repository",
				PathToTag:        "/tag",
				Image:            builtin.KustomizePatchImage{},
			},
			targetImage: types.Image{Name: "repo/demo", NewTag: "v2"},
			assertions: func(t *testing.T, patch string, err error) {
				require.NoError(t, err)
				assert.Contains(t, patch, "value: repo/demo")
				assert.Contains(t, patch, "value: v2")
				assert.Contains(t, patch, "value: keep-me")
				assert.Equal(t, 2, strings.Count(patch, "path: /tag"))
			},
		},
		{
			name: "uses digest syntax for full image path",
			cfg: builtin.KustomizePatchConfig{
				PathToImage: "/image",
				Image:       builtin.KustomizePatchImage{},
			},
			targetImage: types.Image{Name: "repo/demo", Digest: "sha256:abc123"},
			assertions: func(t *testing.T, patch string, err error) {
				require.NoError(t, err)
				assert.Contains(t, patch, "value: repo/demo@sha256:abc123")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch, err := updatePatchOps(tt.patch, tt.cfg, tt.targetImage)
			tt.assertions(t, patch, err)
		})
	}
}

package builtin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/xeipuuv/gojsonschema"
	"go.yaml.in/yaml/v3"
	"sigs.k8s.io/controller-runtime/pkg/client"
	kustypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/resid"

	kargoapi "github.com/akuity/kargo/api/v1alpha1"
	"github.com/akuity/kargo/pkg/controller/freight"
	"github.com/akuity/kargo/pkg/promotion"
	"github.com/akuity/kargo/pkg/x/promotion/runner/builtin"
	intyaml "github.com/akuity/kargo/pkg/yaml"
)

const stepKindKustomizePatch = "kustomize-patch"

func init() {
	promotion.DefaultStepRunnerRegistry.MustRegister(
		promotion.StepRunnerRegistration{
			Name: stepKindKustomizePatch,
			Metadata: promotion.StepRunnerMetadata{
				RequiredCapabilities: []promotion.StepRunnerCapability{
					promotion.StepCapabilityAccessControlPlane,
				},
			},
			Value: newKustomizePatch,
		},
	)
}

// kustomizePatch is an implementation of the promotion.StepRunner interface
// that updates image values inside a Kustomization patch entry.
type kustomizePatch struct {
	schemaLoader gojsonschema.JSONLoader
	kargoClient  client.Client
}

func newKustomizePatch(caps promotion.StepRunnerCapabilities) promotion.StepRunner {
	return &kustomizePatch{
		kargoClient:  caps.KargoClient,
		schemaLoader: getConfigSchemaLoader(stepKindKustomizePatch),
	}
}

// Run implements the promotion.StepRunner interface.
func (k *kustomizePatch) Run(
	ctx context.Context,
	stepCtx *promotion.StepContext,
) (promotion.StepResult, error) {
	cfg, err := k.convert(stepCtx.Config)
	if err != nil {
		return promotion.StepResult{
			Status: kargoapi.PromotionStepStatusFailed,
		}, &promotion.TerminalError{Err: err}
	}
	return k.run(ctx, stepCtx, cfg)
}

func (k *kustomizePatch) convert(cfg promotion.Config) (builtin.KustomizePatchConfig, error) {
	return validateAndConvert[builtin.KustomizePatchConfig](k.schemaLoader, cfg, stepKindKustomizePatch)
}

func (k *kustomizePatch) run(
	ctx context.Context,
	stepCtx *promotion.StepContext,
	cfg builtin.KustomizePatchConfig,
) (promotion.StepResult, error) {
	kusPath, err := findKustomization(stepCtx.WorkDir, cfg.Path)
	if err != nil {
		return promotion.StepResult{Status: kargoapi.PromotionStepStatusErrored},
			fmt.Errorf("could not discover kustomization file: %w", err)
	}

	node, err := readKustomizationFile(kusPath)
	if err != nil {
		return promotion.StepResult{Status: kargoapi.PromotionStepStatusErrored}, err
	}

	currentPatches, err := getCurrentPatches(node)
	if err != nil {
		return promotion.StepResult{Status: kargoapi.PromotionStepStatusErrored}, err
	}

	newPatches, commitMsg, err := k.addPatches(ctx, stepCtx, cfg, currentPatches)
	if err != nil {
		return promotion.StepResult{Status: kargoapi.PromotionStepStatusErrored}, err
	}

	if err = updateKustomizationFilePatch(kusPath, node, newPatches); err != nil {
		return promotion.StepResult{Status: kargoapi.PromotionStepStatusErrored}, err
	}

	result := promotion.StepResult{Status: kargoapi.PromotionStepStatusSucceeded}
	if commitMsg != "" {
		result.Output = map[string]any{
			"commitMessage": commitMsg,
		}
	}
	return result, nil
}

type patchStringValue struct {
	Op    string `json:"op" yaml:"op"`
	Path  string `json:"path" yaml:"path"`
	Value string `json:"value" yaml:"value"`
}

func (k *kustomizePatch) addPatches(
	ctx context.Context,
	stepCtx *promotion.StepContext,
	cfg builtin.KustomizePatchConfig,
	currentPatches []kustypes.Patch,
) ([]kustypes.Patch, string, error) {
	targetImage, err := k.buildTargetImage(ctx, stepCtx, cfg.Image)
	if err != nil {
		return nil, "", err
	}

	patch := kustypes.Patch{
		Target: &kustypes.Selector{
			ResId:         resid.NewResIdKindOnly(cfg.Kind, ""),
			LabelSelector: cfg.LabelSelector,
		},
	}

	count := 0
	newPatches := make([]kustypes.Patch, 0, len(currentPatches)+1)
	for _, p := range currentPatches {
		if p.Target == nil ||
			p.Target.Gvk.Kind != cfg.Kind ||
			p.Target.LabelSelector != cfg.LabelSelector {
			newPatches = append(newPatches, p)
			continue
		}
		count++
		patch = p
	}
	if count > 1 {
		return nil, "", fmt.Errorf("multiple patches (%d) matching criteria were found", count)
	}

	patches, err := updatePatchOps(patch.Patch, cfg, targetImage)
	if err != nil {
		return nil, "", err
	}
	patch.Patch = patches

	newPatches = append(newPatches, patch)
	return newPatches, k.generateCommitMessage(cfg.Path, targetImage), nil
}

func (k *kustomizePatch) buildTargetImage(
	ctx context.Context,
	stepCtx *promotion.StepContext,
	img builtin.KustomizePatchImage,
) (kustypes.Image, error) {
	targetImage := kustypes.Image{
		Name:    img.Image,
		NewName: img.NewName,
	}
	if img.Name != "" {
		targetImage.Name = img.Name
	}

	switch {
	case img.Digest != "":
		targetImage.Digest = img.Digest
	case img.Tag != "":
		targetImage.NewTag = img.Tag
	default:
		var desiredOrigin *kargoapi.FreightOrigin
		if img.FromOrigin != nil {
			desiredOrigin = &kargoapi.FreightOrigin{
				Kind: kargoapi.FreightOriginKind(img.FromOrigin.Kind),
				Name: img.FromOrigin.Name,
			}
		}

		discoveredImage, err := freight.FindImage(
			ctx,
			k.kargoClient,
			stepCtx.Project,
			stepCtx.FreightRequests,
			desiredOrigin,
			stepCtx.Freight.References(),
			img.Image,
		)
		if err != nil {
			return kustypes.Image{}, fmt.Errorf("unable to discover image for %q: %w", img.Image, err)
		}
		if discoveredImage == nil {
			return kustypes.Image{}, fmt.Errorf("unable to discover image for %q", img.Image)
		}

		targetImage.NewTag = discoveredImage.Tag
		if img.UseDigest {
			targetImage.Digest = discoveredImage.Digest
		}
	}

	return targetImage, nil
}

func updatePatchOps(
	patch string,
	cfg builtin.KustomizePatchConfig,
	targetImage kustypes.Image,
) (string, error) {
	fullTag := cfg.PathToImage != ""

	patches := make([]patchStringValue, 0)
	if patch != "" {
		decoder := yaml.NewDecoder(strings.NewReader(patch))
		if err := decoder.Decode(&patches); err != nil {
			return "", fmt.Errorf("unable to decode patches: %w", err)
		}

		filtered := make([]patchStringValue, 0, len(patches))
		for _, patch := range patches {
			if patch.Op == "replace" {
				if fullTag && patch.Path == cfg.PathToImage {
					continue
				}
				if !fullTag && (patch.Path == cfg.PathToRepository || patch.Path == cfg.PathToTag) {
					continue
				}
			}
			filtered = append(filtered, patch)
		}
		patches = filtered
	}

	name := targetImage.NewName
	if name == "" {
		name = targetImage.Name
	}

	version := targetImage.NewTag
	separator := ":"
	if cfg.Image.UseDigest || targetImage.Digest != "" {
		version = targetImage.Digest
		separator = "@"
	}

	if fullTag {
		patches = append(patches, patchStringValue{
			Op:    "replace",
			Path:  cfg.PathToImage,
			Value: fmt.Sprintf("%s%s%s", name, separator, version),
		})
	} else {
		patches = append(patches, patchStringValue{
			Op:    "replace",
			Path:  cfg.PathToRepository,
			Value: name,
		}, patchStringValue{
			Op:    "replace",
			Path:  cfg.PathToTag,
			Value: version,
		})
	}

	b := new(bytes.Buffer)
	if err := yaml.NewEncoder(b).Encode(patches); err != nil {
		return "", fmt.Errorf("unable to encode patches: %w", err)
	}
	return b.String(), nil
}

func (k *kustomizePatch) generateCommitMessage(path string, image kustypes.Image) string {
	var commitMsg strings.Builder
	_, _ = fmt.Fprintf(&commitMsg, "Updated %s to use new image\n", path)

	ref := image.Name
	if image.NewName != "" {
		ref = image.NewName
	}
	if image.NewTag != "" {
		ref = fmt.Sprintf("%s:%s", ref, image.NewTag)
	}
	if image.Digest != "" {
		ref = fmt.Sprintf("%s@%s", ref, image.Digest)
	}

	_, _ = fmt.Fprintf(&commitMsg, "\n- %s", ref)
	return commitMsg.String()
}

func updateKustomizationFilePatch(kusPath string, node *yaml.Node, newPatches []kustypes.Patch) error {
	if err := intyaml.UpdateField(node, "patches", newPatches); err != nil {
		return fmt.Errorf("could not update patches field in Kustomization file: %w", err)
	}
	return writeKustomizationFile(kusPath, node)
}

func getCurrentPatches(node *yaml.Node) ([]kustypes.Patch, error) {
	var curr []kustypes.Patch
	if err := intyaml.DecodeField(node, "patches", &curr); err != nil {
		var fieldErr intyaml.FieldNotFoundErr
		if !errors.As(err, &fieldErr) {
			return nil, fmt.Errorf("could not decode patches field in Kustomization file: %w", err)
		}
	}
	return curr, nil
}

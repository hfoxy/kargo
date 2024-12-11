package directives

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/xeipuuv/gojsonschema"
	kustypes "sigs.k8s.io/kustomize/api/types"
	yaml "sigs.k8s.io/yaml/goyaml.v3"

	kargoapi "github.com/akuity/kargo/api/v1alpha1"
	"github.com/akuity/kargo/internal/controller/freight"
	intyaml "github.com/akuity/kargo/internal/yaml"
)

func init() {
	builtins.RegisterPromotionStepRunner(
		newKustomizePatch(),
		&StepRunnerPermissions{
			AllowKargoClient: true,
		},
	)
}

// kustomizePatch is an implementation  of the PromotionStepRunner
// interface that sets images in a Kustomization file.
type kustomizePatch struct {
	schemaLoader gojsonschema.JSONLoader
}

// newKustomizePatch returns an implementation  of the PromotionStepRunner
// interface that sets images in a Kustomization file.
func newKustomizePatch() PromotionStepRunner {
	return &kustomizePatch{
		schemaLoader: getConfigSchemaLoader("kustomize-set-image"),
	}
}

// Name implements the PromotionStepRunner interface.
func (k *kustomizePatch) Name() string {
	return "kustomize-set-image"
}

// RunPromotionStep implements the PromotionStepRunner interface.
func (k *kustomizePatch) RunPromotionStep(
	ctx context.Context,
	stepCtx *PromotionStepContext,
) (PromotionStepResult, error) {
	failure := PromotionStepResult{Status: kargoapi.PromotionPhaseErrored}

	if err := k.validate(stepCtx.Config); err != nil {
		return failure, err
	}

	// Convert the configuration into a typed object.
	cfg, err := ConfigToStruct[KustomizePatchConfig](stepCtx.Config)
	if err != nil {
		return failure, fmt.Errorf("could not convert config into kustomize-patch config: %w", err)
	}

	return k.runPromotionStep(ctx, stepCtx, cfg)
}

// validate validates kustomizePatch configuration against a JSON schema.
func (k *kustomizePatch) validate(cfg Config) error {
	return validate(k.schemaLoader, gojsonschema.NewGoLoader(cfg), k.Name())
}

func (k *kustomizePatch) runPromotionStep(
	ctx context.Context,
	stepCtx *PromotionStepContext,
	cfg KustomizePatchConfig,
) (PromotionStepResult, error) {
	// Find the Kustomization file.
	kusPath, err := findKustomization(stepCtx.WorkDir, cfg.Path)
	if err != nil {
		return PromotionStepResult{Status: kargoapi.PromotionPhaseErrored},
			fmt.Errorf("could not discover kustomization file: %w", err)
	}

	// Read the Kustomization file, and unmarshal it.
	node, err := readKustomizationFile(kusPath)
	if err != nil {
		return PromotionStepResult{Status: kargoapi.PromotionPhaseErrored}, err
	}

	// Decode the Kustomization file into a typed object to work with.
	currentPatches, err := getCurrentPatches(node)
	if err != nil {
		return PromotionStepResult{Status: kargoapi.PromotionPhaseErrored}, err
	}

	newPatches, commitMsg, err := k.addPatches(ctx, stepCtx, cfg, currentPatches)
	if err != nil {
		return PromotionStepResult{Status: kargoapi.PromotionPhaseErrored}, err
	}

	// Update the Kustomization file with the new images.
	if err = updateKustomizationFilePatch(kusPath, node, newPatches); err != nil {
		return PromotionStepResult{Status: kargoapi.PromotionPhaseErrored}, err
	}

	result := PromotionStepResult{Status: kargoapi.PromotionPhaseSucceeded}
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
	stepCtx *PromotionStepContext,
	cfg KustomizePatchConfig,
	currentPatches []kustypes.Patch,
) ([]kustypes.Patch, string, error) {
	img := cfg.Image

	targetImage := kustypes.Image{
		Name:    img.Image,
		NewName: img.NewName,
	}

	if img.Name != "" {
		targetImage.Name = img.Name
	}

	if img.Digest != "" {
		targetImage.Digest = img.Digest
	} else if img.Tag != "" {
		targetImage.NewTag = img.Tag
	} else {
		var desiredOrigin *kargoapi.FreightOrigin
		if img.FromOrigin != nil {
			desiredOrigin = &kargoapi.FreightOrigin{
				Kind: kargoapi.FreightOriginKind(img.FromOrigin.Kind),
				Name: img.FromOrigin.Name,
			}
		}

		discoveredImage, err := freight.FindImage(
			ctx,
			stepCtx.KargoClient,
			stepCtx.Project,
			stepCtx.FreightRequests,
			desiredOrigin,
			stepCtx.Freight.References(),
			img.Image,
		)

		if err != nil {
			return nil, "", fmt.Errorf("unable to discover image for %q: %w", img.Image, err)
		}

		targetImage.NewTag = discoveredImage.Tag
		if img.UseDigest {
			targetImage.Digest = discoveredImage.Digest
		}
	}

	patch := kustypes.Patch{
		Target: &kustypes.Selector{},
		Patch:  "",
	}

	patch.Target.Kind = cfg.Kind
	patch.Target.LabelSelector = cfg.LabelSelector

	count := 0
	newPatches := make([]kustypes.Patch, 0, len(currentPatches)+1)
	for _, p := range currentPatches {
		if p.Target == nil || p.Target.Kind != cfg.Kind || p.Target.LabelSelector != cfg.LabelSelector {
			newPatches = append(newPatches, p)
			continue
		}

		count++
		patch = p
	}

	if count > 0 {
		return nil, "", fmt.Errorf("multiple patches (%d) matching criteria were found", count)
	}

	fullTag := cfg.PathToImage != ""

	patches := make([]patchStringValue, 0)
	if patch.Patch != "" {
		decoder := yaml.NewDecoder(strings.NewReader(patch.Patch))
		err := decoder.Decode(&patches)
		if err != nil {
			return nil, "", fmt.Errorf("unable to decode patches: %w", err)
		}

		np := make([]patchStringValue, 0, len(patches))
		for _, patch := range patches {
			if patch.Op != "replace" || (fullTag && patch.Path != cfg.PathToImage) || (!fullTag && patch.Path != cfg.PathToRepository && patch.Path != cfg.PathToTag) {
				np = append(np, patch)
				continue
			}
		}
	}

	name := targetImage.NewName
	if name == "" {
		name = targetImage.Name
	}

	tag := targetImage.NewTag
	if cfg.Image.UseDigest {
		tag = targetImage.Digest
	}

	if fullTag {
		patches = append(patches, patchStringValue{
			Op:    "replace",
			Path:  cfg.PathToImage,
			Value: fmt.Sprintf("%s:%s", name, tag),
		})
	} else {
		patches = append(patches, patchStringValue{
			Op:    "replace",
			Path:  cfg.PathToRepository,
			Value: name,
		}, patchStringValue{
			Op:    "replace",
			Path:  cfg.PathToTag,
			Value: tag,
		})
	}

	b := new(bytes.Buffer)
	enc := yaml.NewEncoder(b)

	err := enc.Encode(patches)
	if err != nil {
		return nil, "", fmt.Errorf("unable to encode patches: %w", err)
	}

	patchStr := string(b.Bytes())
	patch.Patch = patchStr

	newPatches = append(newPatches, patch)
	return newPatches, k.generateCommitMessage(cfg.Path, targetImage), nil
}

func (k *kustomizePatch) generateCommitMessage(path string, image kustypes.Image) string {
	var commitMsg strings.Builder
	_, _ = commitMsg.WriteString(fmt.Sprintf("Updated %s to use new image\n", path))

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

	_, _ = commitMsg.WriteString(fmt.Sprintf("\n- %s", ref))
	return commitMsg.String()
}

func updateKustomizationFilePatch(kusPath string, node *yaml.Node, newPatches []kustypes.Patch) error {
	// Update the images field in the Kustomization file.
	if err := intyaml.UpdateField(node, "patches", newPatches); err != nil {
		return fmt.Errorf("could not update images field in Kustomization file: %w", err)
	}

	// Write the updated Kustomization file.
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

func mergePatches(currentPatches []kustypes.Patch, targetPatch kustypes.Patch) []kustypes.Patch {
	newPatches := make([]kustypes.Patch, 0, len(currentPatches)+1)
	for _, patch := range currentPatches {
		if patch.Target == nil {
			newPatches = append(newPatches, patch)
			continue
		}

		if patch.Target.Kind != targetPatch.Target.Kind || patch.Target.LabelSelector != targetPatch.Target.LabelSelector {
			newPatches = append(newPatches, patch)
			continue
		}

		newPatches = append(newPatches, targetPatch)
	}

	return newPatches
}

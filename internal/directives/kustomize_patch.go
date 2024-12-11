package directives

import (
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

	targetPatch, commitMsg, err := k.buildTargetPatchFromConfig(ctx, stepCtx, cfg)
	if err != nil {
		return PromotionStepResult{Status: kargoapi.PromotionPhaseErrored}, err
	}

	// Update the Kustomization file with the new images.
	if err = updateKustomizationFilePatch(kusPath, targetPatch); err != nil {
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

func (k *kustomizePatch) buildTargetPatchFromConfig(
	ctx context.Context,
	stepCtx *PromotionStepContext,
	cfg KustomizePatchConfig,
) (kustypes.Patch, string, error) {
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
			return kustypes.Patch{}, "", fmt.Errorf("unable to discover image for %q: %w", img.Image, err)
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

	return patch, k.generateCommitMessage(cfg.Path, targetImage), nil
}

func (k *kustomizePatch) buildTargetPatchAutomatically(
	_ context.Context,
	_ *PromotionStepContext,
	_ KustomizePatchConfig,
) (kustypes.Patch, string, error) {
	err := errors.New("manual configuration required due to ambiguous result")
	return kustypes.Patch{}, "", err
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

func updateKustomizationFilePatch(kusPath string, patch kustypes.Patch) error {
	// Read the Kustomization file, and unmarshal it.
	node, err := readKustomizationFile(kusPath)
	if err != nil {
		return err
	}

	// Decode the Kustomization file into a typed object to work with.
	currentPatches, err := getCurrentPatches(node)
	if err != nil {
		return err
	}

	// Merge existing images with new images.
	newImages := mergePatches(currentPatches, patch)

	// Update the images field in the Kustomization file.
	if err = intyaml.UpdateField(node, "patches", newImages); err != nil {
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

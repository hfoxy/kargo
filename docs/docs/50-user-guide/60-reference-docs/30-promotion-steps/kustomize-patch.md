---
sidebar_label: kustomize-patch
description: Updates image values inside a Kustomization patch entry.
---

# `kustomize-patch`

`kustomize-patch` updates image values inside the `patches` field of a
Kustomization file. It finds a single patch entry by target `kind` and
`labelSelector`, removes any existing `replace` operations for the configured
image key or keys, and appends replacement operations for the promoted image.

## Configuration

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | `string` | Y | Path to a directory containing a `kustomization.yaml` file. This path is relative to the temporary workspace that Kargo provisions for use by the promotion process. |
| `kind` | `string` | Y | The target kind for the patch entry to update. |
| `labelSelector` | `string` | Y | The target label selector for the patch entry to update. |
| `pathToImage` | `string` | N | JSON pointer path to a full image value, such as `/spec/template/spec/containers/0/image`. Mutually exclusive with `pathToRepository` and `pathToTag`. |
| `pathToRepository` | `string` | N | JSON pointer path to a repository value. Must be used with `pathToTag`. |
| `pathToTag` | `string` | N | JSON pointer path to a tag value. Must be used with `pathToRepository`. |
| `image.image` | `string` | Y | Name/URL of the image being updated. |
| `image.tag` | `string` | N | Tag to set. Mutually exclusive with `image.digest` and `image.useDigest=true`. |
| `image.digest` | `string` | N | Digest to set. Mutually exclusive with `image.tag` and `image.useDigest=true`. |
| `image.useDigest` | `boolean` | N | Use the digest discovered from Freight instead of the tag. |
| `image.fromOrigin` | `object` | N | Freight origin to use when image discovery would otherwise be ambiguous. |
| `image.name` | `string` | N | Name of the image as referenced by the patch target. |
| `image.newName` | `string` | N | New repository/name to write into the patch. |

Either `pathToImage` or both `pathToRepository` and `pathToTag` must be
specified.

## Output

| Name | Type | Description |
|------|------|-------------|
| `commitMessage` | `string` | A description of the change applied by this step. Typically, a subsequent [`git-commit` step](git-commit.md) will reference this output and aggregate this commit message fragment with others like it to build a comprehensive commit message that describes all changes. |

## Examples

```yaml
steps:
- uses: kustomize-patch
  config:
    path: ./src/base
    kind: Deployment
    labelSelector: app.kubernetes.io/name=my-app
    pathToImage: /spec/template/spec/containers/0/image
    image:
      image: ghcr.io/example/my-app
      tag: ${{ imageFrom("ghcr.io/example/my-app").Tag }}
```

```yaml
steps:
- uses: kustomize-patch
  config:
    path: ./src/base
    kind: Deployment
    labelSelector: app.kubernetes.io/name=my-app
    pathToRepository: /spec/template/spec/containers/0/image/repository
    pathToTag: /spec/template/spec/containers/0/image/tag
    image:
      image: ghcr.io/example/my-app
      newName: 123456789012.dkr.ecr.us-west-2.amazonaws.com/my-app
      tag: ${{ imageFrom("ghcr.io/example/my-app").Tag }}
```

package freight

import (
	"context"
	"fmt"
	kargoapi "github.com/akuity/kargo/api/v1alpha1"
	libGit "github.com/akuity/kargo/internal/git"
	"k8s.io/apimachinery/pkg/types"
	"regexp"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type NotFoundError struct {
	msg string
}

func (n NotFoundError) Error() string {
	return n.msg
}

func FindCommit(
	ctx context.Context,
	cl client.Client,
	project string,
	freightReqs []kargoapi.FreightRequest,
	desiredOrigin *kargoapi.FreightOrigin,
	freight []kargoapi.FreightReference,
	repoURL string,
) (*kargoapi.GitCommit, error) {
	repoURL = libGit.NormalizeURL(repoURL)
	// If no origin was explicitly identified, we need to look at all possible
	// origins. If there's only one that could provide the commit we're looking
	// for, great. If there's more than one, there's ambiguity and we need to
	// return an error.
	if desiredOrigin == nil {
		for i := range freightReqs {
			requestedFreight := freightReqs[i]
			warehouse, err := kargoapi.GetWarehouse(
				ctx,
				cl,
				types.NamespacedName{
					Name:      requestedFreight.Origin.Name,
					Namespace: project,
				},
			)
			if err != nil {
				return nil, fmt.Errorf(
					"error getting Warehouse %q in namespace %q: %w",
					requestedFreight.Origin.Name, project, err,
				)
			}
			if warehouse == nil {
				return nil, fmt.Errorf(
					"Warehouse %q not found in namespace %q",
					requestedFreight.Origin.Name, project,
				)
			}
			for _, sub := range warehouse.Spec.Subscriptions {
				if sub.Git != nil && libGit.NormalizeURL(sub.Git.RepoURL) == repoURL {
					if desiredOrigin != nil {
						return nil, fmt.Errorf(
							"multiple requested Freight could potentially provide a "+
								"commit from repo %s; please update promotion steps to "+
								"disambiguate",
							repoURL,
						)
					}
					desiredOrigin = &requestedFreight.Origin
				}
			}
		}
	}
	if desiredOrigin == nil {
		return nil, NotFoundError{
			msg: fmt.Sprintf("commit from repo %s not found in referenced Freight", repoURL),
		}
	}
	// We know exactly what we're after, so this should be easy
	for i := range freight {
		f := &freight[i]
		if f.Origin.Equals(desiredOrigin) {
			for j := range f.Commits {
				c := &f.Commits[j]
				if libGit.NormalizeURL(c.RepoURL) == repoURL {
					return c, nil
				}
			}
		}
	}
	// If we get to here, we looked at all the FreightReferences and didn't find
	// any that came from the desired origin. This could be because no Freight
	// from the desired origin has been promoted yet.
	return nil, NotFoundError{
		msg: fmt.Sprintf("commit from repo %s not found in referenced Freight", repoURL),
	}
}

func FindImage(
	ctx context.Context,
	cl client.Client,
	project string,
	freightReqs []kargoapi.FreightRequest,
	desiredOrigin *kargoapi.FreightOrigin,
	freight []kargoapi.FreightReference,
	repoURL string,
) (*kargoapi.Image, error) {
	// If no origin was explicitly identified, we need to look at all possible
	// origins. If there's only one that could provide the commit we're looking
	// for, great. If there's more than one, there's ambiguity, and we need to
	// return an error.
	if desiredOrigin == nil {
		var match *kargoapi.Image
		for i := range freightReqs {
			requestedFreight := freightReqs[i]
			warehouse, err := kargoapi.GetWarehouse(
				ctx,
				cl,
				types.NamespacedName{
					Name:      requestedFreight.Origin.Name,
					Namespace: project,
				},
			)
			if err != nil {
				return nil, err
			}
			if warehouse == nil {
				return nil, fmt.Errorf(
					"Warehouse %q not found in namespace %q",
					requestedFreight.Origin.Name, project,
				)
			}

			for _, sub := range warehouse.Spec.Subscriptions {
				if sub.Image != nil && sub.Image.RepoURL == repoURL {
					var m *kargoapi.Image
					m, err = findImageFromFreight(desiredOrigin, freight, repoURL, &sub)
					if err != nil {
						return nil, err
					}

					if m != nil && match != nil {
						return nil, fmt.Errorf(
							"multiple requested Freight could potentially provide a container image from "+
								"repository %s: please provide a Freight origin to disambiguate",
							repoURL,
						)
					} else if m != nil {
						match = m
					}
				}
			}
		}

		if match != nil {
			return match, nil
		}
	} else {
		i, err := findImageFromFreight(desiredOrigin, freight, repoURL, nil)
		if err != nil {
			return nil, err
		} else if i != nil {
			return i, nil
		}
	}

	// There is no chance of finding the commit we're looking for. Just return
	// nil and let the caller decide what to do.
	return nil, NotFoundError{
		msg: fmt.Sprintf("image from repo %s not found in referenced Freight", repoURL),
	}
}

func findImageFromFreight(
	desiredOrigin *kargoapi.FreightOrigin,
	freight []kargoapi.FreightReference,
	repoURL string,
	sub *kargoapi.RepoSubscription,
) (*kargoapi.Image, error) {
	for _, f := range freight {
		if desiredOrigin == nil || f.Origin.Equals(desiredOrigin) {
			for _, i := range f.Images {
				if i.RepoURL != repoURL {
					continue
				} else if sub != nil && sub.Image.AllowTags != "" {
					allowTags, err := regexp.Compile(sub.Image.AllowTags)
					if err != nil {
						return nil, fmt.Errorf("invalid AllowTags for subscription (%s): %w", sub.Image.AllowTags, err)
					}

					if !allowTags.MatchString(i.Tag) {
						continue
					}
				}

				return &i, nil
			}
		}
	}

	return nil, nil
}

func HasAmbiguousImageRequest(
	ctx context.Context,
	cl client.Client,
	project string,
	freightReqs []kargoapi.FreightRequest,
) (bool, error) {
	var subscribedRepositories = make(map[string]any)

	for i := range freightReqs {
		requestedFreight := freightReqs[i]
		warehouse, err := kargoapi.GetWarehouse(
			ctx,
			cl,
			types.NamespacedName{
				Name:      requestedFreight.Origin.Name,
				Namespace: project,
			},
		)
		if err != nil {
			return false, err
		}
		if warehouse == nil {
			return false, fmt.Errorf(
				"Warehouse %q not found in namespace %q",
				requestedFreight.Origin.Name, project,
			)
		}

		for _, sub := range warehouse.Spec.Subscriptions {
			if sub.Image != nil {
				if _, ok := subscribedRepositories[sub.Image.RepoURL]; ok {
					return true, fmt.Errorf(
						"multiple requested Freight could potentially provide a container image from repository %s",
						sub.Image.RepoURL,
					)
				}
				subscribedRepositories[sub.Image.RepoURL] = struct{}{}
			}
		}
	}

	return false, nil
}

func FindChart(
	ctx context.Context,
	cl client.Client,
	project string,
	freightReqs []kargoapi.FreightRequest,
	desiredOrigin *kargoapi.FreightOrigin,
	freight []kargoapi.FreightReference,
	repoURL string,
	chartName string,
) (*kargoapi.Chart, error) {
	// If no origin was explicitly identified, we need to look at all possible
	// origins. If there's only one that could provide the commit we're looking
	// for, great. If there's more than one, there's ambiguity, and we need to
	// return an error.
	if desiredOrigin == nil {
		for i := range freightReqs {
			requestedFreight := freightReqs[i]
			warehouse, err := kargoapi.GetWarehouse(
				ctx,
				cl,
				types.NamespacedName{
					Name:      requestedFreight.Origin.Name,
					Namespace: project,
				},
			)
			if err != nil {
				return nil, err
			}
			if warehouse == nil {
				return nil, fmt.Errorf(
					"Warehouse %q not found in namespace %q",
					requestedFreight.Origin.Name, project,
				)
			}
			for _, sub := range warehouse.Spec.Subscriptions {
				if sub.Chart != nil && sub.Chart.RepoURL == repoURL && sub.Chart.Name == chartName {
					if desiredOrigin != nil {
						return nil, fmt.Errorf(
							"multiple requested Freight could potentially provide a chart from "+
								"repository %s: please provide a Freight origin to disambiguate",
							repoURL,
						)
					}
					desiredOrigin = &requestedFreight.Origin
				}
			}
		}
		if desiredOrigin == nil {
			// There is no chance of finding the chart version we're looking for.
			if chartName == "" {
				return nil, NotFoundError{
					msg: fmt.Sprintf("chart from repo %s not found in referenced Freight", repoURL),
				}
			}
			return nil, NotFoundError{
				msg: fmt.Sprintf("chart %q from repo %s not found in referenced Freight", chartName, repoURL),
			}
		}
	}
	// We know exactly what we're after, so this should be easy
	for _, f := range freight {
		if f.Origin.Equals(desiredOrigin) {
			for _, c := range f.Charts {
				if c.RepoURL == repoURL && c.Name == chartName {
					return &c, nil
				}
			}
		}
	}
	// If we get to here, we looked at all the FreightReferences and didn't find
	// any that came from the desired origin. This could be because no Freight
	// from the desired origin has been promoted yet.
	if chartName == "" {
		return nil, NotFoundError{
			msg: fmt.Sprintf("chart from repo %s not found in referenced Freight", repoURL),
		}
	}
	return nil, NotFoundError{
		msg: fmt.Sprintf("chart %q from repo %s not found in referenced Freight", chartName, repoURL),
	}
}

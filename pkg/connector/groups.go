package connector

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/conductorone/baton-scim/pkg/scim"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const groupMembership = "member"

type groupBuilder struct {
	resourceType *v2.ResourceType
	client       *scim.Client
}

func (o *groupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

// Create a new connector resource for a SCIM group.
func groupResource(group scim.Group) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"group_id":   group.ID,
		"group_name": group.DisplayName,
	}

	groupTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	ret, err := rs.NewGroupResource(group.DisplayName, groupResourceType, group.ID, groupTraitOptions)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// List returns all the users from the database as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard user.
func (o *groupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	paginationOptions, bag, err := parseToken(pToken, &v2.ResourceId{ResourceType: groupResourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	groups, nextPage, err := o.client.ListGroups(ctx, paginationOptions, scim.FilterOptions{})
	if err != nil {
		annos := errorAnnotations(err)
		return nil, "", annos, fmt.Errorf("baton-scim: error fetching groups: %w", err)
	}

	var rv []*v2.Resource
	for _, group := range groups {
		resource, err := groupResource(group)
		if err != nil {
			return nil, "", nil, fmt.Errorf("baton-scim: error creating group resource: %w", err)
		}
		rv = append(rv, resource)
	}

	var nextToken string
	if nextPage.NextPage != "" {
		stringToken, err := json.Marshal(nextPage)
		if err != nil {
			return nil, "", nil, err
		}
		nextToken, err = bag.NextToken(string(stringToken))
		if err != nil {
			return nil, "", nil, err
		}
	}

	return rv, nextToken, nil, nil
}

// Entitlements always returns an empty slice for users.
func (o *groupBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement
	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(fmt.Sprintf("%s group %s", resource.DisplayName, groupMembership)),
		ent.WithDescription(fmt.Sprintf("Member of %s group", resource.DisplayName)),
	}

	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		groupMembership,
		assignmentOptions...,
	))

	return rv, "", nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (o *groupBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	group, err := o.client.GetGroup(ctx, resource.Id.Resource)
	if err != nil {
		annos := errorAnnotations(err)
		return nil, "", annos, fmt.Errorf("baton-scim: error fetching group: %w", err)
	}

	var rv []*v2.Grant
	for _, member := range group.Members {
		userCopy := member
		ur, err := rs.NewResourceID(userResourceType, userCopy.ID)
		if err != nil {
			return nil, "", nil, fmt.Errorf("baton-scim: error creating user resource for group %s: %w", resource.Id.Resource, err)
		}

		gr := grant.NewGrant(resource, groupMembership, ur)
		rv = append(rv, gr)
	}

	return rv, "", nil, nil
}

func (g *groupBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"baton-scim: only users can be added to a group",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-scim: only users can be added to a group")
	}

	err := g.client.AddUserToGroup(ctx, entitlement.Resource.Id.Resource, principal.Id.Resource)
	if err != nil {
		return nil, fmt.Errorf("baton-scim: failed to add user to a group: %w", err)
	}

	return nil, nil
}

func (g *groupBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	principal := grant.Principal
	entitlement := grant.Entitlement

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"baton-scim: only users can be removed from a group",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-scim: only users can be removed from a group")
	}

	err := g.client.RemoveUserFromGroup(ctx, entitlement.Resource.Id.Resource, principal.Id.Resource)
	if err != nil {
		return nil, fmt.Errorf("baton-scim: failed to remove user from a group: %w", err)
	}

	return nil, nil
}

func newGroupBuilder(client *scim.Client) *groupBuilder {
	return &groupBuilder{
		resourceType: groupResourceType,
		client:       client,
	}
}

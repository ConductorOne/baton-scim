package connector

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/types/grant"

	"github.com/conductorone/baton-scim/pkg/scim"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/iancoleman/strcase"
	"go.uber.org/zap"
)

const roleMembership = "member"

type roleBuilder struct {
	resourceType *v2.ResourceType
	client       *scim.Client
}

func (o *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

// Create a new connector resource for a SCIM role.
func roleResource(role scim.Role) (*v2.Resource, error) {
	var roleName string
	if role.DisplayName != "" {
		roleName = role.DisplayName
	} else {
		roleName = role.Name
	}

	roleId := strcase.ToSnake(roleName)
	profile := map[string]interface{}{
		"role_id":   roleId,
		"role_name": roleName,
	}

	roleTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	ret, err := rs.NewRoleResource(roleName, roleResourceType, roleId, roleTraitOptions)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// List returns all the users from the database as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard user.
func (o *roleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	paginationOptions, bag, err := parseToken(pToken, &v2.ResourceId{ResourceType: userResourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	// There are mostly no endpoints that fetch roles directly, so we have to fetch users and extract roles from them.
	users, nextPage, err := o.client.ListUsers(ctx, paginationOptions)
	if err != nil {
		annos := errorAnnotations(err)
		return nil, "", annos, fmt.Errorf("baton-scim: error fetching users: %w", err)
	}

	var roles []scim.Role
	for _, user := range users {
		roles = append(roles, user.Roles...)
	}

	var rv []*v2.Resource
	for _, role := range roles {
		resource, err := roleResource(role)
		if err != nil {
			return nil, "", nil, fmt.Errorf("baton-scim: error creating role resource: %w", err)
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
func (o *roleBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement
	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(fmt.Sprintf("%s role %s", resource.DisplayName, roleMembership)),
		ent.WithDescription(fmt.Sprintf("Member of %s role", resource.DisplayName)),
	}

	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		roleMembership,
		assignmentOptions...,
	))

	return rv, "", nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (o *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (g *roleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"baton-scim: only users can be granted a role",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, nil, fmt.Errorf("baton-scim: only users can be granted a role")
	}

	userId, err := rs.NewResourceID(userResourceType, principal.Id.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-scim: error creating user resource id: %w", err)
	}

	err = g.client.AddUserRole(ctx, entitlement.Resource.DisplayName, principal.Id.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-scim: failed to add role to user: %w", err)
	}

	rv := []*v2.Grant{
		grant.NewGrant(principal, roleMembership, userId),
	}

	return rv, nil, nil
}

func (g *roleBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	principal := grant.Principal
	entitlement := grant.Entitlement

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"baton-scim: only users can have a role revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-scim: only users can have a role revoked")
	}

	err := g.client.RevokeUserRole(ctx, entitlement.Resource.DisplayName, principal.Id.Resource)

	if err != nil {
		return nil, fmt.Errorf("baton-scim: failed to revoke user role: %w", err)
	}

	return nil, nil
}

func newRoleBuilder(client *scim.Client) *roleBuilder {
	return &roleBuilder{
		resourceType: roleResourceType,
		client:       client,
	}
}

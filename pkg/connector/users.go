package connector

import (
	"context"
	"encoding/json"
	"fmt"

	scimconfig "github.com/conductorone/baton-scim/pkg/config"
	"github.com/conductorone/baton-scim/pkg/scim"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userBuilder struct {
	resourceType *v2.ResourceType
	client       *scim.Client
	config       *scimconfig.UserMapping
}

func (o *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

// Create a new connector resource for a scim user.
func userResource(user scim.User) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"user_id":    user.ID,
		"login":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"username":   user.UserName,
	}

	userTraitOptions := []resource.UserTraitOption{
		resource.WithUserProfile(profile),
		resource.WithEmail(user.Email, true),
	}

	userStatus := v2.UserTrait_Status_STATUS_ENABLED
	if !user.Active {
		userStatus = v2.UserTrait_Status_STATUS_DISABLED
	}
	userTraitOptions = append(userTraitOptions, resource.WithStatus(userStatus))

	displayName := user.FirstName + " " + user.LastName

	ret, err := resource.NewUserResource(displayName, userResourceType, user.ID, userTraitOptions)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// List returns all the users from the database as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard user.
func (o *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	paginationOptions, bag, err := parseToken(pToken, &v2.ResourceId{ResourceType: userResourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	users, nextPage, err := o.client.ListUsers(ctx, paginationOptions)
	if err != nil {
		annos := errorAnnotations(err)
		return nil, "", annos, fmt.Errorf("baton-scim: error fetching users: %w", err)
	}

	var rv []*v2.Resource
	for _, user := range users {
		resource, err := userResource(user)
		if err != nil {
			return nil, "", nil, fmt.Errorf("baton-scim: error creating user resource: %w", err)
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
func (o *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (o *userBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	user, err := o.client.GetUser(ctx, resource.Id.Resource)
	if err != nil {
		annos := errorAnnotations(err)
		return nil, "", annos, err
	}

	var rv []*v2.Grant
	for _, role := range user.Roles {
		roleResource, err := roleResource(role)
		if err != nil {
			return nil, "", nil, fmt.Errorf("baton-scim: error creating role resource: %w", err)
		}

		gr := grant.NewGrant(roleResource, roleMembership, resource)
		rv = append(rv, gr)
	}

	if o.config.HasGroupsOnUser {
		var group scim.Group
		for _, userGroup := range user.Groups {
			// if there is no ID, we need to look up the group by name to create a resource for grants
			if userGroup.ID == "" {
				groups, _, err := o.client.ListGroups(ctx, scim.PaginationVars{Count: 1, StartIndex: 1}, scim.FilterOptions{Name: userGroup.DisplayName})
				if err != nil {
					return nil, "", nil, fmt.Errorf("baton-scim: error fetching group resource: %w", err)
				}
				group = groups[0]
			} else {
				group = userGroup
			}
			groupResource, err := groupResource(group)
			if err != nil {
				return nil, "", nil, fmt.Errorf("baton-scim: error creating group resource: %w", err)
			}

			gr := grant.NewGrant(groupResource, groupMembership, resource)
			rv = append(rv, gr)
		}
	}

	return rv, "", nil, nil
}

func newUserBuilder(client *scim.Client, config *scimconfig.UserMapping) *userBuilder {
	return &userBuilder{
		resourceType: userResourceType,
		client:       client,
		config:       config,
	}
}

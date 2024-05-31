package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/PaesslerAG/jsonpath"
	scimconfig "github.com/conductorone/baton-scim/pkg/config"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

func extractField(jsonData interface{}, path string) (interface{}, error) {
	if path == "" {
		return nil, nil
	}
	res, err := jsonpath.Get(path, jsonData)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func MapUser(ctx context.Context, resource interface{}, config *scimconfig.UserMapping) (User, error) {
	l := ctxzap.Extract(ctx)
	var user User

	id, err := extractField(resource, config.ID)
	if err != nil {
		return user, err
	}

	user.ID, _ = id.(string)

	firstName, err := extractField(resource, config.FirstName)
	if err != nil {
		return user, err
	}
	user.FirstName, _ = firstName.(string)

	lastName, err := extractField(resource, config.LastName)
	if err != nil {
		return user, err
	}
	user.LastName, _ = lastName.(string)

	email, err := extractPrimaryOrFirstEmail(resource, config)
	if err != nil {
		return user, err
	}
	user.Email = email

	userName, err := extractField(resource, config.Username)
	if err != nil {
		return user, err
	}
	user.UserName, _ = userName.(string)

	active, err := extractField(resource, config.Active)
	if err != nil {
		return user, err
	}

	if activeBool, ok := active.(bool); ok {
		user.Active = activeBool
	}

	roles, err := extractField(resource, config.Roles.Path)
	if err != nil {
		return user, err
	}

	// in some cases the roles are returned as an object instead of an array
	if rolesType := reflect.ValueOf(roles); rolesType.Kind() == reflect.Map {
		r, err := extractRoles(roles, config)
		if err != nil {
			return user, err
		}

		// Only append the role if it has a name
		// In some cases the API returns role objects with empty names, probably due to some permission issues
		if r.Name != "" {
			l.Warn("role name is empty, check your SCIM permissions", zap.Any("role", r))
			user.Roles = append(user.Roles, r)
		}
	} else {
		if rolesSlice, ok := roles.([]interface{}); ok {
			for _, role := range rolesSlice {
				r, err := extractRoles(role, config)
				if err != nil {
					return user, err
				}

				// Only append the role if it has a name
				// In some cases the API returns role objects with empty names, probably due to some permission issues
				if r.Name != "" {
					user.Roles = append(user.Roles, r)
				}
			}
		}
	}

	if config.HasGroupsOnUser {
		groups, err := extractField(resource, config.UserGroup.Path)
		if err != nil {
			return user, err
		}

		if groupsType := reflect.ValueOf(groups); groupsType.Kind() == reflect.Map {
			g, err := extractGroups(groups, &config.UserGroup)
			if err != nil {
				return user, err
			}

			// Only append the group if it has a display name
			if g.DisplayName != "" {
				user.Groups = append(user.Groups, g)
			}
		} else {
			if groupsSlice, ok := groups.([]interface{}); ok {
				for _, group := range groupsSlice {
					g, err := extractGroups(group, &config.UserGroup)
					if err != nil {
						return user, err
					}

					// Only append the group if it has a display name
					if g.DisplayName != "" {
						user.Groups = append(user.Groups, g)
					}
				}
			}
		}
	}

	return user, nil
}

func MapGroup(resource interface{}, config *scimconfig.GroupMapping) (Group, error) {
	var group Group

	id, err := extractField(resource, config.ID)
	if err != nil {
		return group, err
	}
	group.ID, _ = id.(string)

	displayName, err := extractField(resource, config.DisplayName)
	if err != nil {
		return group, err
	}
	group.DisplayName, _ = displayName.(string)

	members, err := extractField(resource, config.Members.Path)
	if err != nil {
		return group, err
	}

	if membersSlice, ok := members.([]interface{}); ok {
		for _, member := range membersSlice {
			var m Member

			memberID, err := extractField(member, config.Members.ID)
			if err != nil {
				return group, err
			}

			m.ID, _ = memberID.(string)

			memberDisplayName, err := extractField(member, config.Members.DisplayName)
			if err != nil {
				return group, err
			}
			m.DisplayName, _ = memberDisplayName.(string)

			group.Members = append(group.Members, m)
		}
	}

	return group, nil
}

func MapPagination(data []byte, config *scimconfig.PaginationMapping) (Pagination, error) {
	var jsonData interface{}
	err := json.Unmarshal(data, &jsonData)
	if err != nil {
		return Pagination{}, fmt.Errorf("unmarshaling data: %w", err)
	}

	totalResults, err := extractField(jsonData, config.TotalResults)
	if err != nil {
		return Pagination{}, err
	}
	itemsPerPage, err := extractField(jsonData, config.ItemsPerPage)
	if err != nil {
		return Pagination{}, err
	}
	startIndex, err := extractField(jsonData, config.StartIndex)
	if err != nil {
		return Pagination{}, err
	}

	return Pagination{
		TotalResults: int(totalResults.(float64)),
		ItemsPerPage: int(itemsPerPage.(float64)),
		StartIndex:   int(startIndex.(float64)),
	}, nil
}

func extractPrimaryOrFirstEmail(jsonData interface{}, config *scimconfig.UserMapping) (string, error) {
	primaryEmail, err := jsonpath.Get(config.PrimaryEmail, jsonData)
	if err == nil {
		if emailList, ok := primaryEmail.([]interface{}); ok && len(emailList) > 0 {
			if email, ok := emailList[0].(string); ok {
				return email, nil
			}
		}
	}

	firstEmail, err := jsonpath.Get(config.FirstEmail, jsonData)
	if err != nil {
		return "", fmt.Errorf("no email found: %w", err)
	}

	if email, ok := firstEmail.(string); ok {
		return email, nil
	}

	return "", fmt.Errorf("no valid email found")
}

func extractRoles(role interface{}, config *scimconfig.UserMapping) (Role, error) {
	var r Role
	roleName, err := extractField(role, config.Roles.Name)
	if err != nil {
		return r, err
	}
	r.Name, _ = roleName.(string)

	roleDisplayName, err := extractField(role, config.Roles.Display)
	if err != nil {
		return r, err
	}

	if roleDisplayName != "" {
		r.DisplayName, _ = roleDisplayName.(string)
	}

	return r, nil
}

func extractGroups(group interface{}, config *scimconfig.UserGroupMapping) (Group, error) {
	var g Group

	id, err := extractField(group, config.ID)
	if err != nil {
		return g, err
	}

	// ID is not always returned by the API if groups are on the user object
	if id != nil {
		g.ID, _ = id.(string)
	}

	displayName, err := extractField(group, config.Name)
	if err != nil {
		return g, err
	}

	g.DisplayName, _ = displayName.(string)

	return g, nil
}

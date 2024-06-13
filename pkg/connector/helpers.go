package connector

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/conductorone/baton-scim/pkg/scim"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type TokenState struct {
	States       []pagination.PageState `json:"states"`
	CurrentState pagination.PageState   `json:"current_state"`
}

func parseToken(token *pagination.Token, resourceId *v2.ResourceId) (scim.PaginationVars, *pagination.Bag, error) {
	b := &pagination.Bag{}

	if token == nil {
		return scim.PaginationVars{}, nil, nil
	}

	state := TokenState{}
	if token.Token != "" {
		err := json.Unmarshal([]byte(token.Token), &state)
		if err != nil {
			return scim.PaginationVars{}, nil, err
		}
	}

	nextToken := scim.Token{}
	if state.CurrentState.Token != "" {
		err := json.Unmarshal([]byte(state.CurrentState.Token), &nextToken)
		if err != nil {
			return scim.PaginationVars{}, nil, err
		}
	}

	paginationOptions := scim.PaginationVars{StartIndex: 0, ItemsReturned: 0}

	if nextToken.NextPage != "" {
		index, err := strconv.Atoi(nextToken.NextPage)
		if err != nil {
			return scim.PaginationVars{}, nil, err
		}
		paginationOptions.StartIndex = index
	}

	if nextToken.ItemsReturned != "" {
		itemsReturned, err := strconv.Atoi(nextToken.ItemsReturned)
		if err != nil {
			return scim.PaginationVars{}, nil, err
		}
		paginationOptions.ItemsReturned = itemsReturned
	}

	if b.Current() == nil {
		b.Push(pagination.PageState{
			ResourceTypeID: resourceId.ResourceType,
			ResourceID:     resourceId.Resource,
		})
	}

	return paginationOptions, b, nil
}

func errorAnnotations(err error) annotations.Annotations {
	annos := annotations.Annotations{}
	var rateLimitErr *scim.RateLimitError
	if errors.As(err, &rateLimitErr) {
		annos.WithRateLimiting(&v2.RateLimitDescription{
			Limit:     0,
			Remaining: 0,
			ResetAt:   timestamppb.New(time.Now().Add(rateLimitErr.RetryAfter)),
		})
		return annos
	}

	return annos
}

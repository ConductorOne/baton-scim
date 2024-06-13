package scim

type User struct {
	ID        string  `json:"id"`
	UserName  string  `json:"userName"`
	FirstName string  `json:"firstName"`
	LastName  string  `json:"lastName"`
	Active    bool    `json:"active"`
	Email     string  `json:"email"`
	Roles     []Role  `json:"roles,omitempty"`
	Groups    []Group `json:"groups,omitempty"`
}

type Group struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`
}

type Member struct {
	ID          string `json:"value"`
	DisplayName string `json:"displayName"`
}

type Role struct {
	Name        string `json:"roleName"`
	DisplayName string `json:"roleDisplay,omitempty"`
}

type Pagination struct {
	TotalResults int `json:"totalResults"`
	ItemsPerPage int `json:"itemsPerPage"`
	StartIndex   int `json:"startIndex"`
}

type Token struct {
	NextPage      string `json:"nextPage"`
	ItemsReturned string `json:"itemsReturned"`
}

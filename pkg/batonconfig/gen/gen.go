package main

import (
	"github.com/conductorone/baton-sdk/pkg/config"
	cfg "github.com/conductorone/baton-scim/pkg/batonconfig"
)

func main() {
	config.Generate("batonconfig", cfg.Config)
}

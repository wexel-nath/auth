package auth

import (
	"fmt"
	"strings"
)

// Permissions is a map of service => []capability
type Permissions map[string][]string

type User struct {
	UserID      int64       `json:"user_id"`
	FirstName   string      `json:"first_name"`
	LastName    string      `json:"last_name"`
	Email       string      `json:"email"`
	Username    string      `json:"username"`
	Permissions Permissions `json:"permissions"`
}

func (u User) IsAuthorized(service string, capabilities []string) error {
	servicePermissions, ok := u.Permissions[strings.ToLower(service)]
	if service != "" && !ok {
		return fmt.Errorf("user is not authorized to use service %s", service)
	}

	if len(capabilities) == 0 {
		return nil
	}

	allPermissions, ok := u.Permissions["all"]
	if !ok {
		allPermissions = []string{}
	}

	permissions := map[string]struct{}{}
	for _, permission := range servicePermissions {
		permissions[permission] = struct{}{}
	}
	for _, permission := range allPermissions {
		permissions[permission] = struct{}{}
	}

	missingCapabilities := make([]string, 0)
	for _, capability := range capabilities {
		if _, ok = permissions[capability]; !ok {
			missingCapabilities = append(missingCapabilities, capability)
		}
	}

	if len(missingCapabilities) > 0 {
		return fmt.Errorf("user is not authorized to use capablities %v", missingCapabilities)
	}

	return nil
}

package auth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUser_IsAuthorized(t *testing.T) {
	type args struct {
		service      string
		capabilities []string
	}
	tests := map[string]struct{
		user User
		args
		want error
	}{
		"no service no capabilities": {
			user: User{},
			args: args{
				service:      "",
				capabilities: nil,
			},
			want: nil,
		},
		"has service no capabilities": {
			user: User{
				Permissions: map[string][]string{
					"fake_service": {},
				},
			},
			args: args{
				service:      "fake_service",
				capabilities: nil,
			},
			want: nil,
		},
		"has service has capabilities": {
			user: User{
				Permissions: map[string][]string{
					"fake_service": { "fake_capability_1" },
				},
			},
			args: args{
				service:      "fake_service",
				capabilities: []string{ "fake_capability_1" },
			},
			want: nil,
		},
		"missing service": {
			user: User{},
			args: args{
				service:      "fake_service",
				capabilities: nil,
			},
			want: errors.New("user is not authorized to use service fake_service"),
		},
		"missing capability": {
			user: User{
				Permissions: map[string][]string{
					"fake_service": {},
				},
			},
			args: args{
				service:      "fake_service",
				capabilities: []string{ "fake_capability_1" },
			},
			want: errors.New("user is not authorized to use capablities [fake_capability_1]"),
		},
		"missing all capabilities": {
			user: User{
				Permissions: map[string][]string{
					"fake_service": {},
				},
			},
			args: args{
				service: "fake_service",
				capabilities: []string{
					"fake_capability_1",
					"fake_capability_2",
				},
			},
			want: errors.New("user is not authorized to use capablities [fake_capability_1 fake_capability_2]"),
		},
		"missing some capabilities": {
			user: User{
				Permissions: map[string][]string{
					"fake_service": { "fake_capability_1" },
				},
			},
			args: args{
				service: "fake_service",
				capabilities: []string{
					"fake_capability_1",
					"fake_capability_2",
					"fake_capability_3",
				},
			},
			want: errors.New("user is not authorized to use capablities [fake_capability_2 fake_capability_3]"),
		},
		"has all-service capability": {
			user: User{
				Permissions: map[string][]string{
					"all": { "fake_capability_1" },
				},
			},
			args: args{
				service:      "",
				capabilities: []string{ "fake_capability_1" },
			},
			want: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(st *testing.T) {
			err := test.user.IsAuthorized(test.service, test.capabilities)

			assert.Equal(st, test.want, err)
		})
	}
}

func TestUser_FullName(t *testing.T) {
	tests := map[string]struct{
		user User
		want string
	}{
		"first middle last": {
			user: User{
				FirstName: "First Middle",
				LastName:  "Last",
			},
			want: "First Middle Last",
		},
		"first last": {
			user: User{
				FirstName: "First",
				LastName:  "Last",
			},
			want: "First Last",
		},
		"only first": {
			user: User{
				FirstName: "First",
				LastName:  "",
			},
			want: "First",
		},
		"only last": {
			user: User{
				FirstName: "",
				LastName:  "Last",
			},
			want: "Last",
		},
	}

	for name, test := range tests {
		t.Run(name, func(st *testing.T) {
			got := test.user.FullName()

			assert.Equal(st, test.want, got)
		})
	}
}

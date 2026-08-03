package vault_test

import (
	"errors"
	"testing"

	"github.com/zuksmaq/vault"
)

func TestNewRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  vault.Config
	}{
		{
			name: "empty config",
			cfg:  vault.Config{},
		},
		{
			name: "no address",
			cfg:  vault.Config{Token: "s.token"},
		},
		{
			name: "no credential",
			cfg:  vault.Config{Address: "https://vault.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := vault.New(tt.cfg); !errors.Is(err, vault.ErrInvalidConfig) {
				t.Fatalf("New() error = %v, want %v", err, vault.ErrInvalidConfig)
			}
		})
	}
}

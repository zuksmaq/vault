package vault_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zuksmaq/vault"
)

func TestUnmarshalBindsTypedValues(t *testing.T) {
	t.Parallel()

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{
			"username": "app",
			"port": 8080,
			"debug": true,
			"timeout": "30s",
			"limits": {"max": 10, "rate": 2.5},
			"hosts": ["a", "b"]
		}`)
	})

	var got struct {
		Username string         `json:"username"`
		Port     int            `json:"port"`
		Debug    bool           `json:"debug"`
		Timeout  vault.Duration `json:"timeout"`
		Limits   struct {
			Max  int     `json:"max"`
			Rate float64 `json:"rate"`
		} `json:"limits"`
		Hosts []string `json:"hosts"`
	}

	if err := client.Unmarshal(context.Background(), "app/config", &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if got.Username != "app" {
		t.Errorf("Username = %q, want %q", got.Username, "app")
	}
	if got.Port != 8080 {
		t.Errorf("Port = %d, want %d", got.Port, 8080)
	}
	if !got.Debug {
		t.Error("Debug = false, want true")
	}
	if want := 30 * time.Second; time.Duration(got.Timeout) != want {
		t.Errorf("Timeout = %v, want %v", time.Duration(got.Timeout), want)
	}
	if got.Limits.Max != 10 {
		t.Errorf("Limits.Max = %d, want %d", got.Limits.Max, 10)
	}
	if got.Limits.Rate != 2.5 {
		t.Errorf("Limits.Rate = %v, want %v", got.Limits.Rate, 2.5)
	}
	if len(got.Hosts) != 2 || got.Hosts[0] != "a" || got.Hosts[1] != "b" {
		t.Errorf("Hosts = %v, want [a b]", got.Hosts)
	}
}

func TestUnmarshalBindsIntoMap(t *testing.T) {
	t.Parallel()

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{"port":8080}`)
	})

	// A map target proves the binding sees the raw secret: coercion would
	// have made this the string "8080" before the caller ever saw it.
	got := map[string]any{}
	if err := client.Unmarshal(context.Background(), "app/config", &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if got["port"] != float64(8080) {
		t.Errorf(`got["port"] = %#v, want the number 8080`, got["port"])
	}
}

func TestUnmarshalDurationForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "seconds", value: `"30s"`, want: 30 * time.Second},
		{name: "compound", value: `"1h30m"`, want: 90 * time.Minute},
		{name: "milliseconds", value: `"1500ms"`, want: 1500 * time.Millisecond},
		{name: "nanoseconds as a number", value: `30000000000`, want: 30 * time.Second},
		{name: "zero", value: `"0s"`, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
				writeSecret(t, w, `{"timeout":`+tt.value+`}`)
			})

			var got struct {
				Timeout vault.Duration `json:"timeout"`
			}
			if err := client.Unmarshal(context.Background(), "app/config", &got); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if time.Duration(got.Timeout) != tt.want {
				t.Errorf("Timeout = %v, want %v", time.Duration(got.Timeout), tt.want)
			}
		})
	}
}

func TestUnmarshalDurationFromNullLeavesFieldAlone(t *testing.T) {
	t.Parallel()

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{"timeout":null}`)
	})

	got := struct {
		Timeout vault.Duration `json:"timeout"`
	}{Timeout: vault.Duration(time.Minute)}

	if err := client.Unmarshal(context.Background(), "app/config", &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if want := time.Minute; time.Duration(got.Timeout) != want {
		t.Errorf("Timeout = %v, want %v left as the caller set it", time.Duration(got.Timeout), want)
	}
}

func TestUnmarshalReportsBindFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		secret string
		target func() any
		// wants is the substring the error must carry, so a caller can
		// see what failed rather than reading a zero value.
		wants string
	}{
		{
			name:   "string into an int field",
			secret: `{"port":"eighty-eighty"}`,
			target: func() any {
				return &struct {
					Port int `json:"port"`
				}{}
			},
			wants: "port",
		},
		{
			name:   "unparseable duration",
			secret: `{"timeout":"half an hour"}`,
			target: func() any {
				return &struct {
					Timeout vault.Duration `json:"timeout"`
				}{}
			},
			wants: "half an hour",
		},
		{
			name:   "duration from a bool",
			secret: `{"timeout":true}`,
			target: func() any {
				return &struct {
					Timeout vault.Duration `json:"timeout"`
				}{}
			},
			wants: "duration",
		},
		{
			name:   "object into a slice field",
			secret: `{"hosts":{"a":1}}`,
			target: func() any {
				return &struct {
					Hosts []string `json:"hosts"`
				}{}
			},
			wants: "hosts",
		},
		{
			name:   "target is not a pointer",
			secret: `{"port":8080}`,
			target: func() any {
				return struct {
					Port int `json:"port"`
				}{}
			},
			wants: "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
				writeSecret(t, w, tt.secret)
			})

			err := client.Unmarshal(context.Background(), "app/config", tt.target())
			if err == nil {
				t.Fatal("Unmarshal() error = nil, want a binding failure")
			}
			if !strings.Contains(err.Error(), tt.wants) {
				t.Errorf("Unmarshal() error = %v, want it to mention %q", err, tt.wants)
			}
			if !strings.Contains(err.Error(), "app/config") {
				t.Errorf("Unmarshal() error = %v, want it to name the secret path", err)
			}
		})
	}
}

func TestUnmarshalLeavesUnmatchedFieldsAlone(t *testing.T) {
	t.Parallel()

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{"port":8080}`)
	})

	// A secret holding only some of a struct's fields binds those and
	// leaves the rest as the caller set them, as encoding/json does.
	got := struct {
		Port int    `json:"port"`
		Host string `json:"host"`
	}{Host: "localhost"}

	if err := client.Unmarshal(context.Background(), "app/config", &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Port != 8080 || got.Host != "localhost" {
		t.Errorf("Unmarshal() = %+v, want {Port:8080 Host:localhost}", got)
	}
}

func TestUnmarshalPropagatesReadFailures(t *testing.T) {
	t.Parallel()

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, `{"errors":[]}`)
	})

	var got struct{}
	err := client.Unmarshal(context.Background(), "app/missing", &got)
	if !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Unmarshal() error = %v, want %v", err, vault.ErrNotFound)
	}
}

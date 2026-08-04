package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Unmarshal binds the secret at path into v through its encoding/json
// tags. It binds the raw decoded secret rather than the strings GetSecrets
// coerces, so int, bool, Duration, nested struct and slice fields receive
// typed values. A secret that will not bind is an error naming the path,
// never a field left silently at its zero value.
func (c *Client) Unmarshal(ctx context.Context, path string, v any) error {
	data, err := c.read(ctx, path)
	if err != nil {
		return err
	}

	// The secret was decoded from JSON, so it encodes again; only the
	// caller's target can fail to bind. Unlike coerce, this encoding may
	// escape <, > and & freely, because the decode below reverses it.
	encoded, _ := json.Marshal(data)
	if err := json.Unmarshal(encoded, v); err != nil {
		return fmt.Errorf("binding %q: %w", path, err)
	}

	// The field names are the caller's, but the values are the secret's,
	// so neither is logged.
	c.logger.DebugContext(ctx, "bound secret",
		"path", path, "mount", c.mountPoint)
	return nil
}

// Duration is a time.Duration that binds from a secret value written the
// way a human writes one — "30s", "1h30m" — since encoding/json alone
// reads a duration only as a count of nanoseconds. Convert it back with
// time.Duration(d).
type Duration time.Duration

// UnmarshalJSON binds a duration written as a string, or as a number of
// nanoseconds for a caller who stores one that way.
func (d *Duration) UnmarshalJSON(data []byte) error {
	// encoding/json leaves a field alone when the value is null, and a
	// duration is no exception.
	if string(data) == "null" {
		return nil
	}

	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		parsed, err := time.ParseDuration(text)
		if err != nil {
			// ParseDuration names the value it could not read.
			return fmt.Errorf("binding duration: %w", err)
		}
		*d = Duration(parsed)
		return nil
	}

	var nanoseconds int64
	if err := json.Unmarshal(data, &nanoseconds); err != nil {
		return fmt.Errorf("binding duration: %s is neither a duration nor a number of nanoseconds", data)
	}
	*d = Duration(nanoseconds)
	return nil
}

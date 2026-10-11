package httpui

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

type inventoryPageQuery struct {
	AfterKey, AfterCursor, Theme string
}

// parseInventoryPageQuery is called only after existing actor/nil admission.
// Complexity: time O(1+U), Omega(1), auxiliary space O(1+U), Omega(1), where U
// is at most4096 raw query bytes (longer input rejects in Theta(1) time/space).
// Tight Theta is not established across malformed-query paths and delegated
// url/base64 allocations. Cursor validation examines at most686 encoded bytes.
func parseInventoryPageQuery(raw string) (inventoryPageQuery, error) {
	invalid := errors.New("invalid extension inventory query")
	if len(raw) > 4096 {
		return inventoryPageQuery{}, invalid
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return inventoryPageQuery{}, invalid
	}
	result := inventoryPageQuery{Theme: inventoryTheme(values.Get("theme"))}
	cursors, present := values["after"]
	if !present {
		return result, nil
	}
	if len(cursors) != 1 || cursors[0] == "" || len(cursors[0]) > 686 || !strings.HasPrefix(cursors[0], "v1.") {
		return inventoryPageQuery{}, invalid
	}
	encoded := strings.TrimPrefix(cursors[0], "v1.")
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(key) != encoded || len(key) > 512 || !utf8.Valid(key) || strings.ContainsRune(string(key), 0) {
		return inventoryPageQuery{}, invalid
	}
	n := utf8.RuneCount(key)
	if n < 3 || n > 128 {
		return inventoryPageQuery{}, invalid
	}
	result.AfterKey = string(key)
	result.AfterCursor = cursors[0]
	return result, nil
}

// inventoryPageCursor preserves stored key bytes; it neither filters rows nor
// invents a new stored-key rejection policy. Supported dataset encoding/key
// compatibility is a separate acceptance gate (SQL_ASCII is not universally
// cursor-compatible). Normal installed IDs are ASCII dotted tokens.
// Complexity: successful time/auxiliary space O(1+K), Omega(1+K), Theta(1+K),
// K key bytes, including base64 output and conversion/concatenation allocations.
func inventoryPageCursor(key string) string {
	return "v1." + base64.RawURLEncoding.EncodeToString([]byte(key))
}

// inventoryPageURL emits only the fixed inventory path, never a return URL.
// Complexity: successful time/auxiliary space O(1+C), Omega(1+C), Theta(1+C),
// C cursor bytes (bounded for admitted cursors); two fixed query keys, normalized
// scalar theme, and delegated URL escaping/building allocations. No row work.
func inventoryPageURL(theme, cursor string) string {
	values := url.Values{"theme": {inventoryTheme(theme)}}
	if cursor != "" {
		values.Set("after", cursor)
	}
	return "/admin/extensions?" + values.Encode()
}

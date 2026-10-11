package extensionsadmin

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"
)

const inventoryPageSize = 50

// InventoryPage is a live inventory selection, not a snapshot or a total count.
type InventoryPage struct {
	Items   []Instance
	HasMore bool
}

// ListInventoryPage reads keys before payloads so lookahead never decodes an
// off-page instance or loads its secret status. Selected errors return no page.
// A selected key disappearing between reads fails rather than refilling a page.
// SQL ordering is authoritative; the existing unique product/extension key is
// required. Legacy List and the per-instance scanner/status semantics are intact.
// Complexity: time O(1+K+B+G+Q), Omega(1); auxiliary space O(1+K+B+G+M),
// Omega(1). Tight Theta bounds are not established across errors, SQL and driver
// work. K is at most 51 key strings of at most 512 bytes, B selected full-payload
// bytes, G selected grant/status processing bytes and entries, Q delegated SQL,
// driver and decoding time, M delegated driver/decoder storage. At most 50 full
// instances are materialized; B/G, database tuple visits and waits are not capped.
// Input validation examines at most 512 bytes; longer input rejects in Theta(1)
// time/space. Successful SQL calls: one when empty, otherwise two plus item count.
func (s *Service) ListInventoryPage(ctx context.Context, afterKey string) (InventoryPage, error) {
	if afterKey != "" {
		if len(afterKey) > 512 || !utf8.ValidString(afterKey) || strings.ContainsRune(afterKey, 0) {
			return InventoryPage{}, errors.New("invalid inventory position")
		}
		n := utf8.RuneCountInString(afterKey)
		if n < 3 || n > 128 {
			return InventoryPage{}, errors.New("invalid inventory position")
		}
	}
	query := "SELECT extension_id FROM extension_instances WHERE product=$1 ORDER BY extension_id LIMIT 51"
	args := []any{Product}
	if afterKey != "" {
		query = "SELECT extension_id FROM extension_instances WHERE product=$1 AND extension_id>$2 ORDER BY extension_id LIMIT 51"
		args = append(args, afterKey)
	}
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return InventoryPage{}, err
	}
	defer rows.Close()
	keys := make([]string, 0, inventoryPageSize+1)
	for rows.Next() {
		if len(keys) == inventoryPageSize+1 {
			return InventoryPage{}, errors.New("invalid inventory key population")
		}
		var key string
		if err := rows.Scan(&key); err != nil {
			return InventoryPage{}, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return InventoryPage{}, err
	}
	if err := rows.Close(); err != nil {
		return InventoryPage{}, err
	}
	if len(keys) == 0 {
		return InventoryPage{}, nil
	}
	hasMore := len(keys) > inventoryPageSize
	if hasMore {
		keys = keys[:inventoryPageSize]
	}
	rows, err = s.DB.QueryContext(ctx, "SELECT "+instanceColumns+" FROM extension_instances WHERE product=$1 AND extension_id=ANY($2::text[]) ORDER BY extension_id", Product, postgresTextArray(keys))
	if err != nil {
		return InventoryPage{}, err
	}
	defer rows.Close()
	items := make([]Instance, 0, len(keys))
	for rows.Next() {
		item, err := scanInstance(rows)
		if err != nil {
			return InventoryPage{}, err
		}
		// Both reads use the same database ordering. Position equality also detects
		// wrong/duplicate membership without another map or a Go collation substitute.
		if len(items) >= len(keys) || item.ExtensionID != keys[len(items)] {
			return InventoryPage{}, errors.New("inventory selection changed")
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return InventoryPage{}, err
	}
	if err := rows.Close(); err != nil {
		return InventoryPage{}, err
	}
	if len(items) != len(keys) {
		return InventoryPage{}, errors.New("inventory selection changed")
	}
	for i := range items {
		if err := s.loadSecretStatus(ctx, &items[i]); err != nil {
			return InventoryPage{}, err
		}
	}
	return InventoryPage{Items: items, HasMore: hasMore}, nil
}

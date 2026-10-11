package httpui

import (
	"errors"
	"net/url"
	"strconv"
)

var errPermissionsPageQuery = errors.New("invalid permissions page query")
var errPermissionsPageRange = errors.New("permissions page not found")
var errPermissionsCount = errors.New("permissions count overflow")

type permissionsPageQuery struct {
	Page  uint64
	Theme string
}
type permissionsPageView struct {
	Capabilities, Interfaces, SecretSlots []string
	Number, Pages                         int
}

// Complexity: O(1+U) time/auxiliary space, Omega(1), U<=4096 raw query bytes;
// longer queries reject in Theta(1). ParseQuery allocations/error paths are
// delegated; no universal tight Theta. Decimal validation examines at most19 bytes.
// Called only for authenticated, loaded, metadata-valid normal detail GET.
func parsePermissionsPageQuery(raw string) (permissionsPageQuery, error) {
	if len(raw) > 4096 {
		return permissionsPageQuery{}, errPermissionsPageQuery
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return permissionsPageQuery{}, errPermissionsPageQuery
	}
	q := permissionsPageQuery{Page: 1, Theme: inventoryTheme(values.Get("theme"))}
	pages, present := values["permissions_page"]
	if !present {
		return q, nil
	}
	if len(pages) != 1 || len(pages[0]) == 0 || len(pages[0]) > 19 {
		return permissionsPageQuery{}, errPermissionsPageQuery
	}
	s := pages[0]
	if s[0] < '1' || s[0] > '9' {
		return permissionsPageQuery{}, errPermissionsPageQuery
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return permissionsPageQuery{}, errPermissionsPageQuery
		}
	}
	q.Page, err = strconv.ParseUint(s, 10, 63)
	if err != nil {
		return permissionsPageQuery{}, errPermissionsPageQuery
	}
	return q, nil
}

// Complexity: Theta(1) time and auxiliary space: exactly three category lengths
// and at most three borrowed sub-slices. No element/string copies or sorting;
// backing arrays remain retained by the loaded Item. Does not bound service,
// full-form, escaped-entry-byte, template or response-buffer costs.
func permissionsWindow(capabilities, interfaces, slots []string, page uint64) (permissionsPageView, error) {
	lists := [3][]string{capabilities, interfaces, slots}
	total := 0
	for _, list := range lists {
		if len(list) > int(^uint(0)>>1)-total {
			return permissionsPageView{}, errPermissionsCount
		}
		total += len(list)
	}
	pages := 1
	if total > 0 {
		pages = 1 + (total-1)/25
	}
	if page == 0 || page > uint64(pages) {
		return permissionsPageView{}, errPermissionsPageRange
	}
	offset := (int(page) - 1) * 25
	remaining := min(25, total-offset)
	var selected [3][]string
	for i, list := range lists {
		if offset >= len(list) {
			offset -= len(list)
			continue
		}
		count := min(remaining, len(list)-offset)
		if count > 0 {
			selected[i] = list[offset : offset+count]
		}
		remaining -= count
		offset = 0
	}
	return permissionsPageView{Capabilities: selected[0], Interfaces: selected[1], SecretSlots: selected[2], Number: int(page), Pages: pages}, nil
}

// Complexity: Theta(1+P) time/auxiliary output space for P authorized route bytes,
// including delegated PathEscape, decimal conversion (<=19 digits) and string
// concatenation. No Host/raw query is copied; display-only, never a form action.
func permissionsPageURL(route, theme string, page int) string {
	target := extensionDetailActionURL(route, theme)
	if page > 1 {
		target += "&permissions_page=" + strconv.Itoa(page)
	}
	return target + "#permissions"
}

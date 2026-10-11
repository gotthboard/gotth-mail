package httpui

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// Test-only fixed malformed/valid query matrix; work/storage includes query bytes and parser delegates.
func TestPermissionsQuery(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		page  uint64
		theme string
	}{
		{"", 1, "system"}, {"permissions_page=1", 1, "system"}, {"permissions_page=26&theme=dark", 26, "dark"}, {"permissions%5fpage=%32&theme=light&theme=dark", 2, "light"}, {"permissions_page=9223372036854775807", 9223372036854775807, "system"}, {"unknown=x&theme=no", 1, "system"}, {"x=" + strings.Repeat("x", 4094), 1, "system"},
	} {
		t.Run(tc.raw[:min(len(tc.raw), 50)], func(t *testing.T) {
			q, e := parsePermissionsPageQuery(tc.raw)
			if e != nil || q.Page != tc.page || q.Theme != tc.theme {
				t.Fatalf("query=%+v err=%v", q, e)
			}
		})
	}
	for _, raw := range []string{"permissions_page=", "permissions_page=0", "permissions_page=01", "permissions_page=-1", "permissions_page=+1", "permissions_page=%2B1", "permissions_page=1e2", "permissions_page=１２", "permissions_page=1&permissions_page=2", "permissions_page=1&permissions%5Fpage=1", "permissions_page=%", "x=a;b", "permissions_page=9223372036854775808", "permissions_page=10000000000000000000", "x=" + strings.Repeat("x", 4095)} {
		t.Run("invalid-"+raw[:min(len(raw), 45)], func(t *testing.T) {
			if _, e := parsePermissionsPageQuery(raw); e == nil {
				t.Fatal("accepted malformed query")
			}
		})
	}
}

// Test-only O(N) fixture/oracle storage and traversal; N generated entries, plus fixed page selection calls.
func TestPermissionsWindow(t *testing.T) {
	for _, counts := range [][3]int{{0, 0, 0}, {25, 0, 0}, {26, 0, 0}, {24, 1, 1}, {25, 1, 25}, {26, 0, 50}, {0, 25, 1}, {0, 0, 26}, {10, 30, 40}} {
		t.Run(fmt.Sprint(counts), func(t *testing.T) {
			var lists [3][]string
			var want, got []string
			for k, n := range counts {
				for i := 0; i < n; i++ {
					value := fmt.Sprintf("%d:%d", k, i)
					lists[k] = append(lists[k], value)
					want = append(want, value)
				}
			}
			if counts[0] > 1 {
				lists[0][1] = lists[0][0]
				want[1] = want[0]
			}
			before := fmt.Sprint(lists)
			pages := max(1, (len(want)+24)/25)
			for n := 1; n <= pages; n++ {
				v, e := permissionsWindow(lists[0], lists[1], lists[2], uint64(n))
				if e != nil || v.Number != n || v.Pages != pages {
					t.Fatalf("page %+v %v", v, e)
				}
				size := len(v.Capabilities) + len(v.Interfaces) + len(v.SecretSlots)
				if size > 25 {
					t.Fatal("per-category instead of combined limit")
				}
				for k, s := range [][]string{v.Capabilities, v.Interfaces, v.SecretSlots} {
					if len(s) > 0 {
						found := false
						for i := range lists[k] {
							if &s[0] == &lists[k][i] {
								found = true
							}
						}
						if !found {
							t.Fatal("not borrowed subslice")
						}
					}
					got = append(got, s...)
				}
			}
			if !reflect.DeepEqual(got, want) || fmt.Sprint(lists) != before {
				t.Fatal("order/occurrence/source mutation")
			}
			for _, n := range []uint64{0, uint64(pages + 1), 1<<63 - 1} {
				if _, e := permissionsWindow(lists[0], lists[1], lists[2], n); e != errPermissionsPageRange {
					t.Fatalf("range %d: %v", n, e)
				}
			}
		})
	}
}

// Test-only fixed URL cases; costs include escaped route bytes and URL parser allocations.
func TestPermissionsURL(t *testing.T) {
	for _, page := range []int{0, 1, 2, 100} {
		s := permissionsPageURL("alias?/#<>", "dark", page)
		u, e := url.Parse(s)
		if e != nil || u.Host != "" || u.Path != "/admin/extensions/alias?/#<>" || u.Fragment != "permissions" || u.Query().Get("theme") != "dark" {
			t.Fatalf("unsafe url %q %v", s, e)
		}
		if page <= 1 {
			if u.Query().Has("permissions_page") {
				t.Fatal("firstpage spelling")
			}
		} else if u.Query().Get("permissions_page") != fmt.Sprint(page) {
			t.Fatal("lost page")
		}
	}
	if !strings.Contains(permissionsPageURL("id", "unknown", 1), "theme=system") {
		t.Fatal("theme normalization")
	}
}

// Test-only fixed inventory admission/fallback cases; no I/O or registry reads.
func TestPermissionsInventoryLinks(t *testing.T) {
	for _, id := range []string{"", "not-a-uuid", "00000000-0000-4000-8000-00000000009z"} {
		if inventoryPermissionsURL(id, "dark") != "/admin/extensions?theme=dark" {
			t.Fatal("invalid ID fallback")
		}
	}
	if inventoryPermissionsURL("00000000-0000-4000-8000-000000000099", "bad") != "/admin/extensions/00000000-0000-4000-8000-000000000099?theme=system#permissions" {
		t.Fatal("normal view link")
	}
}

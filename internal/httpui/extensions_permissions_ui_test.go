package httpui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"golang.org/x/net/html"
)

// Test-only DOM oracle: O(B) parse/walk time and space for response bytes B.
func permissionsDOM(t *testing.T, body string) ([]string, map[string]string) {
	t.Helper()
	root, e := html.Parse(strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	var values []string
	links := map[string]string{}
	walkUpdateHTML(root, func(n *html.Node) {
		if n.Data == "a" {
			links[updateAttr(n, "id")] = updateAttr(n, "href")
		}
		if updateAttr(n, "id") == "permissions" {
			walkUpdateHTML(n, func(q *html.Node) {
				if q.Data == "li" {
					var b strings.Builder
					walkUpdateHTML(q, func(c *html.Node) {
						if c.Type == html.TextNode {
							b.WriteString(c.Data)
						}
					})
					values = append(values, b.String())
				}
			})
		}
	})
	return values, links
}

// Test-only fixture setup and real handler traversal; SQL/renderer costs delegated.
func TestPermissionsHTTP(t *testing.T) {
	f := newMetadataRecoveryFixture(t)
	var lists [3][]string
	for k := range lists {
		for i := 0; i < 26; i++ {
			lists[k] = append(lists[k], fmt.Sprintf("group%d.p%02d", k, i))
		}
	}
	lists[0][1] = lists[0][0]
	encoded := make([]string, 3)
	for i := range lists {
		b, e := json.Marshal(lists[i])
		metadataRecoveryCheck(t, e)
		encoded[i] = string(b)
	}
	_, e := f.db.Exec("UPDATE extension_instances SET capabilities_json=$1::jsonb,interfaces_json=$2::jsonb,secret_slots_json=$3::jsonb WHERE instance_id=$4", encoded[0], encoded[1], encoded[2], metadataRecoveryID)
	metadataRecoveryCheck(t, e)
	request := func(raw string, auth bool, hx string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/admin/extensions/"+metadataRecoveryID, nil)
		r.URL.RawQuery = raw
		r.Header.Set("HX-Request", hx)
		if auth {
			withIdentityCookies(r, "metadata-recovery-session", metadataRecoveryCSRF)
		}
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		return w
	}
	_, e = f.db.Exec("UPDATE extension_instances SET secret_slots_json='[]'::jsonb WHERE instance_id=$1", metadataRecoveryOther)
	metadataRecoveryCheck(t, e)
	before := targetUISnapshot(t, f.db)
	var all []string
	for page := 1; page <= 4; page++ {
		w := request(fmt.Sprintf("theme=dark&permissions_page=%d", page), true, "true")
		if w.Code != 200 {
			t.Fatalf("page%d status%d", page, w.Code)
		}
		got, links := permissionsDOM(t, w.Body.String())
		want := 25
		if page == 4 {
			want = 3
		}
		if len(got) != want {
			t.Errorf("page%d entries%d want%d", page, len(got), want)
		}
		all = append(all, got...)
		if !strings.HasPrefix(strings.ToLower(w.Body.String()), "<!doctype html>") || !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'none'") {
			t.Error("detail HX/full/CSP")
		}
		if (links["permissions-previous"] != "") != (page > 1) || (links["permissions-next"] != "") != (page < 4) {
			t.Error("pager boundary")
		}
		_, values, _ := updateForm(t, w.Body.String(), "update-preview")
		for i, key := range []string{"capabilities", "interfaces", "secret_slots"} {
			if values.Get(key) != strings.Join(lists[i], ",") {
				t.Error("truncated authority input", key)
			}
		}
		root, _ := html.Parse(strings.NewReader(w.Body.String()))
		walkUpdateHTML(root, func(n *html.Node) {
			if n.Data == "form" && updateAttr(n, "action") != extensionDetailActionURL(metadataRecoveryID, "dark") {
				t.Error("page leaked into action")
			}
			if n.Data == "nav" && updateAttr(n, "aria-label") == "Detail theme" {
				walkUpdateHTML(n, func(a *html.Node) {
					if a.Data == "a" {
						u, _ := url.Parse(updateAttr(a, "href"))
						want := ""
						if page > 1 {
							want = fmt.Sprint(page)
						}
						if u.Query().Get("permissions_page") != want {
							t.Error("theme lost page")
						}
					}
				})
			}
		})
	}
	var expected []string
	for _, list := range lists {
		expected = append(expected, list...)
	}
	if !reflect.DeepEqual(all, expected) {
		t.Error("stable traversal mismatch")
	}
	for _, tc := range []struct {
		raw    string
		auth   bool
		status int
	}{{"permissions_page=", true, 400}, {"permissions_page=0", true, 400}, {"permissions_page=5", true, 404}, {"permissions_page=1&permissions%5fpage=2", true, 400}, {"bad=%", true, 400}, {"x=" + strings.Repeat("x", 4095), true, 400}, {"permissions_page=9223372036854775808", true, 400}, {"permissions_page=PRIVATE%", false, 401}} {
		w := request(tc.raw, tc.auth, "")
		if w.Code != tc.status {
			t.Errorf("input status%d want%d", w.Code, tc.status)
		}
		if strings.Contains(w.Body.String(), "PRIVATE") {
			t.Error("input reflection")
		}
	}
	for _, page := range []int{1, 2} {
		r := httptest.NewRequest("GET", "/admin/extensions/"+metadataRecoveryOther+"?theme=light&permissions_page="+fmt.Sprint(page), nil)
		withIdentityCookies(r, "metadata-recovery-session", metadataRecoveryCSRF)
		out := httptest.NewRecorder()
		f.handler.ServeHTTP(out, r)
		if page == 1 {
			entries, links := permissionsDOM(t, out.Body.String())
			if out.Code != 200 || len(entries) != 0 || links["permissions-next"] != "" || links["permissions-previous"] != "" || !strings.Contains(out.Body.String(), "No granted permissions.") {
				t.Error("empty page1")
			}
		} else if out.Code != 404 {
			t.Error("empty page2")
		}
	}
	for _, hx := range []string{"", "true"} {
		r := httptest.NewRequest("GET", "/admin/extensions?theme=dark", nil)
		r.Header.Set("HX-Request", hx)
		withIdentityCookies(r, "metadata-recovery-session", metadataRecoveryCSRF)
		out := httptest.NewRecorder()
		f.handler.ServeHTTP(out, r)
		root, _ := html.Parse(strings.NewReader(out.Body.String()))
		found := 0
		walkUpdateHTML(root, func(n *html.Node) {
			if updateAttr(n, "data-extension-id") == metadataRecoveryID {
				walkUpdateHTML(n, func(c *html.Node) {
					if updateAttr(c, "data-permission-count") != "" {
						if c.FirstChild == nil || c.FirstChild.Data != "26" {
							t.Error("inventory count")
						}
						found++
					}
					if updateAttr(c, "data-permissions-link") == "true" && updateAttr(c, "href") != inventoryPermissionsURL(metadataRecoveryID, "dark") {
						t.Error("inventory link")
					}
				})
			}
		})
		if out.Code != 200 || found != 3 {
			t.Error("inventory full/fragment counts")
		}
	}
	if !reflect.DeepEqual(before, targetUISnapshot(t, f.db)) || len(f.runtime.calls) != 0 {
		t.Fatal("GET mutation")
	}
	// Existing POST parser ignores valid unknown page state; error retains full lists.
	for _, action := range []string{"invalid-action", "update-preview"} {
		v := url.Values{"action": {action}, "csrf_token": {metadataRecoveryCSRF}, "artifact_pin": {"sha256:" + strings.Repeat("5", 64)}, "manifest_sha256": {strings.Repeat("6", 64)}, "grant_sha256": {strings.Repeat("7", 64)}, "session_sha256": {strings.Repeat("8", 64)}}
		for i, key := range []string{"capabilities", "interfaces", "secret_slots"} {
			v.Set(key, strings.Join(lists[i], ","))
		}
		if action == "update-preview" {
			for k, key := range []string{"capabilities", "interfaces", "secret_slots"} {
				var target []string
				for i := 0; i < 30; i++ {
					target = append(target, fmt.Sprintf("target%d.p%02d", k, i))
				}
				v.Set(key, strings.Join(target, ","))
			}
		}
		r := formReq("POST", extensionDetailActionURL(metadataRecoveryID, "dark")+"&permissions_page=999", v, "")
		withIdentityCookies(r, "metadata-recovery-session", metadataRecoveryCSRF)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("POST paging changed status", w.Code)
		}
		got, _ := permissionsDOM(t, w.Body.String())
		if len(got) != 25 || got[0] != lists[0][0] {
			t.Error("POST not display page1")
		}
		_, values, _ := updateForm(t, w.Body.String(), "update-preview")
		for i, key := range []string{"capabilities", "interfaces", "secret_slots"} {
			if values.Get(key) != strings.Join(lists[i], ",") {
				t.Error("POST truncated inputs")
			}
		}
		if action == "update-preview" {
			if !strings.Contains(w.Body.String(), "Reviewed update") {
				t.Fatal("real preview missing")
			}
			root, parseErr := html.Parse(strings.NewReader(w.Body.String()))
			metadataRecoveryCheck(t, parseErr)
			paragraphs := map[string]string{}
			walkUpdateHTML(root, func(n *html.Node) {
				if n.Data == "p" {
					var text strings.Builder
					walkUpdateHTML(n, func(c *html.Node) {
						if c.Type == html.TextNode {
							text.WriteString(c.Data)
						}
					})
					for _, label := range []string{"Privilege diff:", "Configuration-schema diff:", "Secret-slot diff:"} {
						if strings.HasPrefix(text.String(), label) {
							paragraphs[label] = strings.TrimSpace(strings.TrimPrefix(text.String(), label))
						}
					}
				}
			})
			// Existing service PrivilegeDiff is capability-only; interfaces remain
			// bound in the target, not a newly invented display-diff category.
			for _, check := range []struct {
				index      int
				key, label string
			}{{0, "capabilities", "Privilege diff:"}, {2, "secret_slots", "Secret-slot diff:"}} {
				oldSet := map[string]bool{}
				for _, token := range lists[check.index] {
					oldSet[token] = true
				}
				var expectedDiff []string
				for token := range oldSet {
					expectedDiff = append(expectedDiff, "-"+token)
				}
				for _, token := range strings.Split(v.Get(check.key), ",") {
					expectedDiff = append(expectedDiff, "+"+token)
				}
				sort.Strings(expectedDiff)
				if len(expectedDiff) <= 25 || paragraphs[check.label] != strings.Join(expectedDiff, ", ") {
					t.Error("real POST incomplete approval diff", check.label)
				}
			}
			// This UI does not edit metadata: an invented nonempty schema diff
			// would change its contract. All three >25 diffs are component-tested.
			if value, present := paragraphs["Configuration-schema diff:"]; !present || value != "" {
				t.Error("unexpected metadata edit")
			}
			_, apply, confirmation := updateForm(t, w.Body.String(), "update-apply")
			if confirmation == "" {
				t.Fatal("missing issued confirmation")
			}
			apply.Set("confirmation", "wrong")
			unchanged := targetUISnapshot(t, f.db)
			errReq := formReq("POST", extensionDetailActionURL(metadataRecoveryID, "dark")+"&permissions_page=2", apply, "")
			withIdentityCookies(errReq, "metadata-recovery-session", metadataRecoveryCSRF)
			denied := httptest.NewRecorder()
			f.handler.ServeHTTP(denied, errReq)
			if denied.Code != 200 || !strings.Contains(denied.Body.String(), "extension confirmation rejected") || strings.Contains(denied.Body.String(), "Reviewed update") || !reflect.DeepEqual(unchanged, targetUISnapshot(t, f.db)) {
				t.Fatal("confirmation failure semantics/state changed")
			}
			_, retained, _ := updateForm(t, denied.Body.String(), "update-preview")
			for i, key := range []string{"capabilities", "interfaces", "secret_slots"} {
				if retained.Get(key) != strings.Join(lists[i], ",") {
					t.Error("confirmation error truncated full form")
				}
			}
			entries, _ := permissionsDOM(t, denied.Body.String())
			if len(entries) != 25 || entries[0] != lists[0][0] {
				t.Error("confirmation error changed default readonly page")
			}
		}
	}
	// Normal GET never reloads the displayed POST preview.
	if strings.Contains(request("permissions_page=2", true, "").Body.String(), "Reviewed update") {
		t.Error("GET persisted preview")
	}
	f.corrupt(t, metadataRecoveryRaw("unknown", ""))
	w := request("theme=dark&permissions_page=PRIVATE%", true, "")
	metadataRecoveryDocument(t, w)
	_, e = f.db.Exec("UPDATE extension_instances SET metadata_json='[]'::jsonb WHERE instance_id=$1", metadataRecoveryID)
	metadataRecoveryCheck(t, e)
	if got := request("theme=dark&permissions_page=PRIVATE%", true, ""); got.Code != 400 || !strings.Contains(got.Body.String(), "extension operation failed") {
		t.Error("decode precedence")
	}
	_, e = f.db.Exec("DELETE FROM extension_operation_previews WHERE instance_id=$1", metadataRecoveryID)
	metadataRecoveryCheck(t, e)
	// A different syntactically valid nonexistent target must preserve404 before parsing.
	r := httptest.NewRequest("GET", "/admin/extensions/00000000-0000-4000-8000-000000000099", nil)
	r.URL.RawQuery = "permissions_page=PRIVATE%"
	withIdentityCookies(r, "metadata-recovery-session", metadataRecoveryCSRF)
	notfound := httptest.NewRecorder()
	f.handler.ServeHTTP(notfound, r)
	if notfound.Code != 404 {
		t.Error("Get missing precedence", notfound.Code)
	}
}

// Pure components: O(fixture+rendered bytes), including complete large form/diff data.
func TestPermissionsComponents(t *testing.T) {
	var names, diffs []string
	for i := 0; i < 30; i++ {
		names = append(names, fmt.Sprintf("entry.%02d", i))
		diffs = append(diffs, fmt.Sprintf("diff.%02d<&", i))
	}
	names[0] = "<script>&'"
	item := extensionsadmin.Instance{InstanceID: "00000000-0000-4000-8000-000000000099", Capabilities: names, Interfaces: names, SecretSlots: names}
	var out strings.Builder
	if e := inventoryRows(inventoryView{Items: []extensionsadmin.Instance{item}, Theme: "dark"}).Render(context.Background(), &out); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "entry.29") || !strings.Contains(out.String(), "View permissions") || !strings.Contains(out.String(), "theme=dark#permissions") {
		t.Error("inventory not counts/link")
	}
	for _, failed := range []bool{false, true} {
		view := extensionPageView{Item: item, ActionURL: extensionDetailActionURL(item.InstanceID, "dark"), CSRF: "fixture-csrf", OperationError: failed, Preview: extensionsadmin.Preview{ID: "fixture-preview", Operation: "update", Confirmation: "fixture-confirmation", PrivilegeDiff: diffs, ConfigurationDiff: diffs, SecretSlotDiff: diffs}}
		out.Reset()
		if e := extensionDetailDocument(view, item.InstanceID, "dark").Render(context.Background(), &out); e != nil {
			t.Fatal(e)
		}
		body := out.String()
		got, _ := permissionsDOM(t, body)
		if len(got) != 25 || got[0] != names[0] {
			t.Error("default component first page/escaping")
		}
		_, v, _ := updateForm(t, body, "update-preview")
		for _, key := range []string{"capabilities", "interfaces", "secret_slots"} {
			if v.Get(key) != strings.Join(names, ",") {
				t.Error("full component input")
			}
		}
		root, _ := html.Parse(strings.NewReader(body))
		var text strings.Builder
		walkUpdateHTML(root, func(n *html.Node) {
			if n.Data == "script" {
				t.Error("script injection")
			}
			if n.Type == html.TextNode {
				text.WriteString(n.Data)
			}
		})
		for _, d := range diffs {
			if strings.Count(text.String(), d) != 3 {
				t.Error("all3 full diff lists missing", d)
			}
		}
	}
}

// Admission-only cases avoid touching a nil/unauthorized service.
func TestPermissionsAdmission(t *testing.T) {
	for _, tc := range []struct {
		token  string
		svc    *extensionsadmin.Service
		status int
	}{{"", &extensionsadmin.Service{}, 401}, {"Bearer page-test-denied", &extensionsadmin.Service{}, 403}, {"Bearer page-test-admin", nil, 503}} {
		h := paginationHandler(t, tc.svc)
		r := httptest.NewRequest("GET", "/admin/extensions/target", nil)
		r.URL.RawQuery = "permissions_page=PRIVATE%"
		r.Header.Set("Authorization", tc.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("precedence %d want%d", w.Code, tc.status)
		}
	}
}

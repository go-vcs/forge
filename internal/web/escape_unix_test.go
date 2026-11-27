// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package web_test

import (
	"strings"
	"testing"
)

// The file names below cannot exist on Windows, hence the build tag.
func TestBrowseEscapesEverything(t *testing.T) {
	r, opt := newRepos(t)
	e := newEnv(t, opt)
	r.commit(t, "<img src=x onerror=alert(1)>", map[string][]byte{
		"<b>x<i>.txt":   []byte("<script>alert(1)</script>\n"),
		"a b?#.txt":     []byte("space\n"),
		"q\"'><u>.txt":  []byte("quote\n"),
		"jav\tascript:": nil,
	})
	c := e.anon()
	base := e.ts.URL + "/alice/pub"
	sha := r.head(t, "pub")
	pages := []string{"", "/tree/main", "/blob/main/%3Cb%3Ex%3Ci%3E.txt", "/commits/main", "/commit/" + sha}
	for _, p := range pages {
		code, _, b := fetch(t, c, base+p)
		if code != 200 {
			t.Fatalf("%q: %d", p, code)
		}
		for _, bad := range []string{"<script", "<img src=x", "<b>x", "<u>", `onerror=alert(1)>`} {
			if strings.Contains(b, bad) {
				t.Errorf("%q: unescaped %q", p, bad)
			}
		}
		if strings.Contains(b, "<style") || strings.Contains(b, " style=") {
			t.Errorf("%q: inline style", p)
		}
	}
	// the link of an awkward name leads to that name
	code, _, b := fetch(t, c, base+"/tree/main")
	href := `href="/alice/pub/blob/main/a%20b%3F%23.txt"`
	if code != 200 || !strings.Contains(b, href) {
		t.Fatalf("no %s in\n%s", href, b)
	}
	code, _, b = fetch(t, c, base+"/blob/main/a%20b%3F%23.txt")
	if code != 200 || !strings.Contains(b, "space") {
		t.Errorf("a b?#.txt: %d", code)
	}
}

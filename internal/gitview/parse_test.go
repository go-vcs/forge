// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package gitview

import (
	"strings"
	"testing"
)

func TestParseEntry(t *testing.T) {
	id := strings.Repeat("a", 40)
	ok := map[string]Entry{
		"100644 blob " + id + "     12\tf.txt":   {Mode: "100644", Type: "blob", ID: id, Name: "f.txt", Size: 12},
		"040000 tree " + id + "      -\td e":     {Mode: "040000", Type: "tree", ID: id, Name: "d e", Size: -1},
		"160000 commit " + id + "    -\ttab\tin": {Mode: "160000", Type: "commit", ID: id, Name: "tab\tin", Size: -1},
		"100644 blob " + id + "      0\t-":       {Mode: "100644", Type: "blob", ID: id, Name: "-", Size: 0},
	}
	for in, want := range ok {
		if got, good := parseEntry(in); !good || got != want {
			t.Errorf("parseEntry(%q) = %+v, %v; want %+v", in, got, good, want)
		}
	}
	for _, in := range []string{"", "garbage", "100644 blob " + id + " 5 f.txt", "100644 blob " + id + "\tf.txt", "100644 blob " + id + " 5 6\tf.txt",
		"100644 blob " + id + " 5\t", "100644 blob " + id + " x\tf.txt", "100644 blob " + id + " -5\tf.txt", "100644 blob " + id + " 99999999999999999999\tf.txt"} {
		if got, good := parseEntry(in); good {
			t.Errorf("parseEntry(%q) = %+v, want a refusal", in, got)
		}
	}
}

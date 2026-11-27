// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package web

import "net/http"

// Page is page, for tests: a template that does not exist.
func (s *Server) Page(w http.ResponseWriter, name string) {
	s.page(w, http.StatusOK, name, nil)
}

// SafeNext is safeNext, for tests.
func SafeNext(n string) string { return safeNext(n) }

// FlowCount is the number of sign-ins in progress.
func (s *Server) FlowCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.flows)
}

package gomitmproxy

import (
	"net/http"
	"testing"
)

func TestProxyAuthorizeBasicSchemeIsCaseInsensitive(t *testing.T) {
	const username = "fixture-user"
	const password = "fixture-password"

	p := &Proxy{Config: Config{Username: username, Password: password}}
	validCredentials := basicAuth(username, password)
	cases := []struct {
		name       string
		header     string
		wantAuthor bool
	}{
		{name: "canonical scheme", header: "Basic " + validCredentials, wantAuthor: true},
		{name: "lowercase scheme", header: "basic " + validCredentials, wantAuthor: true},
		{name: "mixed case scheme", header: "bAsIc " + validCredentials, wantAuthor: true},
		{name: "wrong password", header: "basic " + basicAuth(username, "wrong"), wantAuthor: false},
		{name: "unsupported scheme", header: "Bearer " + validCredentials, wantAuthor: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Header: make(http.Header)}
			req.Header.Set("Proxy-Authorization", tc.header)
			session := &Session{ctx: &Context{}, req: req}

			gotAuthor, gotResponse := p.authorize(session)
			if gotResponse != nil {
				defer gotResponse.Body.Close()
			}
			if gotAuthor != tc.wantAuthor {
				t.Fatalf("authorize() = %v, want %v", gotAuthor, tc.wantAuthor)
			}
			if tc.wantAuthor && gotResponse != nil {
				t.Fatalf("authorize() response = %v, want nil", gotResponse)
			}
			if !tc.wantAuthor && (gotResponse == nil || gotResponse.StatusCode != http.StatusProxyAuthRequired) {
				t.Fatalf("authorize() response = %v, want 407", gotResponse)
			}
		})
	}
}

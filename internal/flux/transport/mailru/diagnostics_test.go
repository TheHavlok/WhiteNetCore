package mailru

import (
	"strings"
	"testing"
)

// A link pasted from the address bar keeps its query or fragment; sent on as
// part of "public" it names a file that does not exist.
func TestNormalizeWeblink(t *testing.T) {
	cases := map[string]string{
		"AbCdEfGh1/IjKlMnOp2":                                           "AbCdEfGh1/IjKlMnOp2",
		"https://cloud.mail.ru/public/AbCdEfGh1/IjKlMnOp2":              "AbCdEfGh1/IjKlMnOp2",
		"https://cloud.mail.ru/public/AbCdEfGh1/IjKlMnOp2/":             "AbCdEfGh1/IjKlMnOp2",
		"https://cloud.mail.ru/public/AbCdEfGh1/IjKlMnOp2?weblink=x":    "AbCdEfGh1/IjKlMnOp2",
		"https://cloud.mail.ru/public/AbCdEfGh1/IjKlMnOp2#top":          "AbCdEfGh1/IjKlMnOp2",
		"  http://cloud.mail.ru/public/AbCdEfGh1/IjKlMnOp2?a=1&b=2#c  ": "AbCdEfGh1/IjKlMnOp2",
		"/AbCdEfGh1/IjKlMnOp2/":                                         "AbCdEfGh1/IjKlMnOp2",
	}
	for in, want := range cases {
		if got := normalizeWeblink(in); got != want {
			t.Errorf("normalizeWeblink(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every message about the session itself has to be recognised, or a refused
// session looks exactly like a slow one.
func TestDescribeServerMessage(t *testing.T) {
	cases := []struct {
		name, text, kind, detailHas string
	}{
		{"auth ok", `42["message",{"type":"auth","result":1,"sessionId":"x"}]`, "auth-ok", ""},
		{"auth refused", `42["message",{"type":"auth","result":0,"description":"access deny"}]`, "auth-refused", "access deny"},
		{"error", `42["message",{"type":"error","description":"Error: Document not found","code":4}]`, "error", "code 4"},
		{"drop", `42["message",{"type":"drop","description":"session expired"}]`, "drop", "session expired"},
		{"connect error", `44{"message":"invalid token"}`, "connect-error", "invalid token"},
		{"alone", `42["message",{"type":"connectState","participants":[{"id":"a"}]}]`, "participants", "1 participant"},
		{"peer here", `42["message",{"type":"connectState","participants":[{"id":"a"},{"id":"b"}]}]`, "participants", "2 participant"},
		{"cursor data is not a note", `42["message",{"type":"cursor","messages":[{"cursor":"18;QUJD"}]}]`, "", ""},
		{"ping", `2`, "", ""},
		{"engine open", `0{"sid":"abc"}`, "", ""},
		{"garbage", `42[not json`, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := describeServerMessage(tc.text)
			if got.kind != tc.kind {
				t.Fatalf("kind = %q, want %q (detail %q)", got.kind, tc.kind, got.detail)
			}
			if tc.detailHas != "" && !strings.Contains(got.detail, tc.detailHas) {
				t.Fatalf("detail = %q, want it to mention %q", got.detail, tc.detailHas)
			}
		})
	}
}

func TestSnippetBounded(t *testing.T) {
	if got := snippet(nil); got != "empty body" {
		t.Fatalf("snippet(nil) = %q", got)
	}
	long := strings.Repeat("x", 500)
	if got := snippet([]byte(long)); len(got) > 210 {
		t.Fatalf("snippet is not bounded: %d bytes", len(got))
	}
}

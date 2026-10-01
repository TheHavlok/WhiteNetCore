package main

import (
	"strings"
	"testing"
)

func TestBlankTokenLine(t *testing.T) {
	body := `# WhiteNet node agent configuration.
main = "panel.example.com:8443"

# The one-time enrolment token.
token = "s3cr3t-token-value"
ca_fingerprint = "abc123"

[reconnect]
initial_delay = "1s"
`
	updated, changed := blankTokenLine(body)
	if !changed {
		t.Fatal("the token line was not changed")
	}
	if strings.Contains(updated, "s3cr3t-token-value") {
		t.Error("the token is still in the file")
	}
	if !strings.Contains(updated, `token = ""`) {
		t.Errorf("the token line was not blanked:\n%s", updated)
	}
	// Everything else has to survive, comments included.
	for _, want := range []string{
		"# WhiteNet node agent configuration.",
		`main = "panel.example.com:8443"`,
		`ca_fingerprint = "abc123"`,
		"[reconnect]",
		`initial_delay = "1s"`,
	} {
		if !strings.Contains(updated, want) {
			t.Errorf("the file lost %q:\n%s", want, updated)
		}
	}

	// Blanking an already-blank token must report no change, so the file is
	// not rewritten on every start.
	if _, changed := blankTokenLine(updated); changed {
		t.Error("an already-blank token reported a change")
	}
	// A file with no token at all must be left alone.
	if _, changed := blankTokenLine("main = \"x:1\"\n"); changed {
		t.Error("a file without a token reported a change")
	}
	// A commented-out token is not the setting.
	if _, changed := blankTokenLine("# token = \"old\"\nmain = \"x:1\"\n"); changed {
		t.Error("a commented token was treated as the setting")
	}
	// Indentation is preserved.
	indented, changed := blankTokenLine("  token = \"x\"\n")
	if !changed || !strings.HasPrefix(indented, "  token") {
		t.Errorf("indentation was lost: %q", indented)
	}
}

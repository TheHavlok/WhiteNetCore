package client

import "testing"

// Xray's banner line is seventy-odd characters and the panel stores it in a
// short column, so the version has to be pulled out of it rather than kept
// whole. Getting this wrong made every node's hello fail.
func TestCompactVersion(t *testing.T) {
	cases := map[string]string{
		"Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go1.26.1 linux/amd64)": "26.3.27",
		"Xray 1.8.4 (Xray, Penetrates Everything.) abcdef0":                          "1.8.4",
		"xray version v25.1.30": "25.1.30",
		"whitenet 1.0.0":        "1.0.0",
		"test-2":                "test-2",
		"":                      "",
	}
	for line, want := range cases {
		if got := compactVersion(line); got != want {
			t.Errorf("compactVersion(%q) = %q, want %q", line, got, want)
		}
	}

	// A line with nothing version-shaped in it must still be short enough to
	// store.
	long := ""
	for i := 0; i < 100; i++ {
		long += "x"
	}
	if got := compactVersion(long); len(got) > 60 {
		t.Errorf("a long unrecognisable line was kept at %d characters", len(got))
	}
}

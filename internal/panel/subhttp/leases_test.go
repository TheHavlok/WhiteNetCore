package subhttp

import "testing"

// An exit listens on a wildcard so it accepts on every interface. Handing
// that to a client as a dial address would have it connect to itself, which
// is the kind of thing that looks like a transport failure.
func TestDialAddress(t *testing.T) {
	cases := []struct {
		listen, node, want string
	}{
		{"0.0.0.0:8444", "138.124.19.145", "138.124.19.145:8444"},
		{":8444", "138.124.19.145", "138.124.19.145:8444"},
		{"[::]:8444", "138.124.19.145", "138.124.19.145:8444"},
		{"*:8444", "138.124.19.145", "138.124.19.145:8444"},
		// An explicit address is what the operator meant; keep it.
		{"203.0.113.9:8444", "138.124.19.145", "203.0.113.9:8444"},
		// A node with no address configured cannot be dialled at all, so the
		// carrier is left out rather than given a wildcard.
		{"0.0.0.0:8444", "", ""},
		// Not host:port: pass it through rather than guess.
		{"a-unix-socket", "138.124.19.145", "a-unix-socket"},
		{"", "138.124.19.145", ""},
		// An IPv6 node address has to come back bracketed.
		{"0.0.0.0:8444", "2001:db8::1", "[2001:db8::1]:8444"},
	}
	for _, tc := range cases {
		if got := dialAddress(tc.listen, tc.node); got != tc.want {
			t.Errorf("dialAddress(%q, %q) = %q, want %q", tc.listen, tc.node, got, tc.want)
		}
	}
}

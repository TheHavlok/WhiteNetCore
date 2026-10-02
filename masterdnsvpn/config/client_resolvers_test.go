// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientResolversSupportsIPCIDRAndPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	content := `
8.8.8.8
1.1.1.1:5353
192.168.10.0/30:5300
[2001:db8::1]:5400
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolvers, resolverMap, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers returned error: %v", err)
	}

	if len(resolvers) != 5 {
		t.Fatalf("unexpected resolver count: got=%d want=%d", len(resolvers), 5)
	}
	if resolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected default port: got=%d want=%d", resolverMap["8.8.8.8"], 53)
	}
	if resolverMap["1.1.1.1"] != 5353 {
		t.Fatalf("unexpected custom port: got=%d want=%d", resolverMap["1.1.1.1"], 5353)
	}
	if resolverMap["192.168.10.1"] != 5300 || resolverMap["192.168.10.2"] != 5300 {
		t.Fatalf("unexpected cidr expansion map: %+v", resolverMap)
	}
	if resolverMap["2001:db8::1"] != 5400 {
		t.Fatalf("unexpected IPv6 port: got=%d want=%d", resolverMap["2001:db8::1"], 5400)
	}
}

func TestLoadClientResolversRejectsHugeCIDR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(path, []byte("10.0.0.0/8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if _, _, err := LoadClientResolvers(path); err == nil {
		t.Fatal("LoadClientResolvers should still fail when no valid resolvers remain")
	}
}

func TestLoadClientResolversDropsDuplicateIPsEvenWithDifferentPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	content := `
8.8.8.8:53
8.8.8.8:5353
8.8.8.8:53
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolvers, resolverMap, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers returned error: %v", err)
	}

	if len(resolvers) != 1 {
		t.Fatalf("unexpected resolver count: got=%d want=%d", len(resolvers), 1)
	}
	if resolvers[0].IP != "8.8.8.8" || resolvers[0].Port != 53 {
		t.Fatalf("unexpected resolver entry: %+v", resolvers[0])
	}
	if resolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected resolver map port: got=%d want=%d", resolverMap["8.8.8.8"], 53)
	}
}

func TestLoadClientResolversSkipsInvalidEntriesAndKeepsValidOnes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	content := `
bad ip
8.8.8.8
10.0.0.0/8
1.1.1.1:5353
8.8.8.8:9999
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolvers, resolverMap, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers returned error: %v", err)
	}

	if len(resolvers) != 2 {
		t.Fatalf("unexpected resolver count: got=%d want=%d", len(resolvers), 2)
	}
	if resolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected port for 8.8.8.8: got=%d want=%d", resolverMap["8.8.8.8"], 53)
	}
	if resolverMap["1.1.1.1"] != 5353 {
		t.Fatalf("unexpected port for 1.1.1.1: got=%d want=%d", resolverMap["1.1.1.1"], 5353)
	}
}

// A list from a subscription or an app profile goes through the same parser
// as the resolver file, keeps its order, and drops what it cannot use.
func TestParseResolverList(t *testing.T) {
	got, ports := ParseResolverList([]string{
		"77.88.8.8",
		" 195.208.4.1:5353 ",
		"# a comment",
		"",
		"not-an-address",
		"77.88.8.8:53", // the same address again
		"[2a02:6b8::feed:0ff]:53",
	})
	want := []ResolverAddress{
		{IP: "77.88.8.8", Port: 53},
		{IP: "195.208.4.1", Port: 5353},
		{IP: "2a02:6b8::feed:ff", Port: 53},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %v, want %v (all: %v)", i, got[i], want[i], got)
		}
	}
	if ports["195.208.4.1"] != 5353 {
		t.Fatalf("resolver map = %v", ports)
	}
}

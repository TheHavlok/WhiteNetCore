package main

import "strings"

// blankTokenLine empties the token assignment in a TOML file, leaving every
// other line untouched. A spent token is a credential nobody needs, and
// rewriting the whole file from the parsed configuration would lose comments
// the installer put there.
func blankTokenLine(body string) (updated string, changed bool) {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, _, found := strings.Cut(trimmed, "=")
		if !found || strings.TrimSpace(key) != "token" {
			continue
		}
		// Keep the original indentation, so a file an operator formatted
		// stays formatted.
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		replacement := indent + `token = ""`
		if lines[i] == replacement {
			return body, false
		}
		lines[i] = replacement
		return strings.Join(lines, "\n"), true
	}
	return body, false
}

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/thehavlok/whitenet/internal/panel/sharelink"
)

const linkUsage = `wn-main link - build and read whitenet:// links

Usage:
  wn-main link make [FILE]       Read a bundle as JSON (FILE or stdin), print the link
  wn-main link read [LINK]       Print a link's bundle as JSON (LINK or stdin)
  wn-main link qr [LINK]         Print a link's QR code for a terminal
  wn-main link import URL        Build the whitenetvpn://import deep link for a subscription URL

A bundle is {"name": "...", "servers": [...], "sub": "https://..."} where each
server is one object of the subscription format. See docs/panel/LINKS.md.

Neither subcommand needs a configuration file or a database, so this works on
a workstation for testing a link by hand.
`

// cmdLink is deliberately outside the configured commands: a link is
// self-contained, so reading or writing one must not need a database.
func cmdLink(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, linkUsage)
		return errors.New("link needs a subcommand: make, read, qr or import")
	}

	switch args[0] {
	case "make":
		raw, err := readInput(args[1:])
		if err != nil {
			return err
		}
		var bundle sharelink.Bundle
		if err := json.Unmarshal(raw, &bundle); err != nil {
			return fmt.Errorf("link make: the input is not a bundle: %w", err)
		}
		link, err := sharelink.Encode(bundle)
		if err != nil {
			return err
		}
		fmt.Println(link)
		return nil

	case "read":
		raw, err := readInput(args[1:])
		if err != nil {
			return err
		}
		bundle, err := sharelink.Decode(strings.TrimSpace(string(raw)))
		if err != nil {
			return fmt.Errorf("%w (code %s)", err, sharelink.ErrorCode(err))
		}
		out, err := json.MarshalIndent(bundle, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil

	case "qr":
		raw, err := readInput(args[1:])
		if err != nil {
			return err
		}
		link := strings.TrimSpace(string(raw))
		// Decode first: printing a QR code of an unusable link wastes
		// whoever scans it.
		if _, err := sharelink.Decode(link); err != nil {
			if _, importErr := sharelink.ParseImportLink(link); importErr != nil {
				return fmt.Errorf("link qr: %w", err)
			}
		}
		art, err := sharelink.Terminal(link)
		if err != nil {
			return err
		}
		fmt.Println(art)
		fmt.Println(link)
		return nil

	case "import":
		if len(args) < 2 {
			return errors.New("link import needs a subscription URL")
		}
		link, err := sharelink.ImportLink(args[1])
		if err != nil {
			return err
		}
		fmt.Println(link)
		return nil

	default:
		fmt.Fprint(os.Stderr, linkUsage)
		return fmt.Errorf("link: unknown subcommand %q", args[0])
	}
}

// readInput takes the first argument, or stdin when there is none or it is "-".
func readInput(args []string) ([]byte, error) {
	if len(args) > 0 && args[0] != "-" {
		// A path is read as a file; anything else is taken literally, so a
		// link can be passed on the command line.
		if raw, err := os.ReadFile(args[0]); err == nil {
			return raw, nil
		}
		return []byte(args[0]), nil
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	return raw, nil
}

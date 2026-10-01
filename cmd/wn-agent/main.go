// Command wn-agent is the WhiteNet node agent. It enrols with Main, keeps one
// bidirectional gRPC stream open over mutual TLS, and runs the node's cores:
// xray-core and the WhiteNet DNS tunnel as supervised processes, and the flux
// exit channels inside this process.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/thehavlok/whitenet/internal/agentd/client"
	"github.com/thehavlok/whitenet/internal/agentd/config"
	"github.com/thehavlok/whitenet/internal/wnlog"
)

const usage = `wn-agent - WhiteNet node agent

Usage:
  wn-agent [-config FILE] run
  wn-agent [-config FILE] enroll [-token TOKEN] [-main HOST:PORT] [-ca-fingerprint HEX]
  wn-agent [-config FILE] status
  wn-agent version

Commands:
  run      Connect to Main and run the cores (what systemd runs)
  enroll   Exchange a one-time token for a client certificate and exit
  status   Print the local identity, the applied state version and the cores
  version  Print the agent version

Flags:
  -config FILE   Configuration file (default: $WN_AGENT_CONFIG, then
                 ` + config.DefaultPath + `)

Anything in the configuration can be overridden through the environment with
the WN_AGENT_ prefix: WN_AGENT_MAIN, WN_AGENT_TOKEN, WN_AGENT_CA_FINGERPRINT.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "wn-agent: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("wn-agent", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	configPath := fs.String("config", defaultConfigPath(), "configuration file")
	token := fs.String("token", "", "one-time enrolment token (enroll)")
	mainAddr := fs.String("main", "", "Main's agent endpoint, host:port (enroll)")
	fingerprint := fs.String("ca-fingerprint", "", "Main's CA fingerprint (enroll)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return errors.New("no command given")
	}
	if rest[0] == "version" {
		fmt.Println(client.Version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		// Enrolment is the one command that has to work before there is a
		// usable configuration file, so its flags can supply what is missing.
		if rest[0] != "enroll" || *mainAddr == "" {
			return err
		}
		cfg = config.Default()
	}
	// Flags win over the file, so an operator can re-enrol a node against a
	// different panel without editing anything.
	if *mainAddr != "" {
		cfg.Main = *mainAddr
	}
	if *fingerprint != "" {
		cfg.CAFingerprint = *fingerprint
	}
	if *token != "" {
		cfg.Token = *token
	}

	log := wnlog.New(cfg.Log.Level, cfg.Log.Format)
	agent := client.New(cfg, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch rest[0] {
	case "run":
		return cmdRun(ctx, agent, cfg)
	case "enroll":
		return cmdEnroll(ctx, agent, cfg, *configPath)
	case "status":
		return cmdStatus(agent)
	default:
		fs.Usage()
		return fmt.Errorf("unknown command %q", rest[0])
	}
}

func defaultConfigPath() string {
	if v, ok := os.LookupEnv("WN_AGENT_CONFIG"); ok {
		return v
	}
	return config.DefaultPath
}

func cmdRun(ctx context.Context, agent *client.Agent, cfg config.Config) error {
	// A node installed and then left unenrolled is a common state: the
	// installer writes the token and starts the service, and the service
	// enrols itself on first start.
	if !agent.Identity().Enrolled() {
		if cfg.Token == "" {
			return errors.New("this node is not enrolled and has no token; run `wn-agent enroll -token TOKEN`")
		}
		if err := agent.Enrol(ctx, cfg.Token); err != nil {
			return err
		}
		// The token is spent, so remove it from the file: a copy left behind
		// is a credential nobody needs.
		if err := clearToken(defaultConfigPath()); err != nil {
			return err
		}
	}
	return agent.Run(ctx)
}

func cmdEnroll(ctx context.Context, agent *client.Agent, cfg config.Config, configPath string) error {
	if agent.Identity().Enrolled() {
		uuid, err := agent.Identity().NodeUUID()
		if err != nil {
			return err
		}
		return fmt.Errorf("this node is already enrolled as %s; remove %s to enrol again",
			uuid, cfg.DataDir)
	}
	if cfg.Token == "" {
		return errors.New("enroll needs -token, or token in the configuration file")
	}
	if err := agent.Enrol(ctx, cfg.Token); err != nil {
		return err
	}
	uuid, err := agent.Identity().NodeUUID()
	if err != nil {
		return err
	}
	fmt.Printf("enrolled as %s\n", uuid)
	return clearToken(configPath)
}

func cmdStatus(agent *client.Agent) error {
	id := agent.Identity()
	if !id.Enrolled() {
		fmt.Println("not enrolled")
		return nil
	}
	uuid, err := id.NodeUUID()
	if err != nil {
		return err
	}
	notAfter, err := id.NotAfter()
	if err != nil {
		return err
	}
	fmt.Printf("node:        %s\n", uuid)
	fmt.Printf("certificate: valid until %s\n", notAfter.Format("2006-01-02 15:04:05 MST"))

	// The applied state comes from disk, so status works whether or not the
	// agent is running.
	state, err := agent.Applier().LoadPersisted()
	if err != nil {
		fmt.Printf("state:       unreadable (%v)\n", err)
		return nil
	}
	if state == nil {
		fmt.Println("state:       none applied yet")
		return nil
	}
	fmt.Printf("state:       version %d, %d inbounds, %d users\n",
		state.GetVersion(), len(state.GetInbounds()), len(state.GetUsers()))
	if flux := state.GetOpenflux(); flux != nil && flux.GetEnabled() {
		fmt.Printf("flux:        mode %s, %d channels\n", flux.GetMode(), len(flux.GetChannels()))
	}
	return nil
}

// clearToken blanks the token in the configuration file once it has been
// spent. The file keeps its other contents; only the one line changes.
func clearToken(path string) error {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("clear token in %s: %w", path, err)
	}
	updated, changed := blankTokenLine(string(raw))
	if !changed {
		return nil
	}
	return os.WriteFile(path, []byte(updated), 0o600)
}

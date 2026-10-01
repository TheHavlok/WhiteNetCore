package noderpc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"crypto/tls"
	"crypto/x509"

	"github.com/thehavlok/whitenet/internal/nodepb"
	"github.com/thehavlok/whitenet/internal/panel/nodeca"
	"github.com/thehavlok/whitenet/internal/panel/secret"
	"github.com/thehavlok/whitenet/internal/panel/staterender"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

// Options configure the server.
type Options struct {
	// AgentCertTTL is how long an agent certificate is valid.
	AgentCertTTL time.Duration
	// Hosts are the names Main's own certificate covers. Agents verify
	// against the pinned CA, so this only has to match however they dial.
	Hosts []string
	// LogRetention bounds how much of a fetched node log is kept in memory
	// waiting for the API to collect it.
	LogBuffer int
}

// Server implements both agent-facing services.
type Server struct {
	nodepb.UnimplementedRegistrationServer
	nodepb.UnimplementedNodeControlServer

	store    *store.Store
	box      *secret.Box
	ca       *CAManager
	hub      *Hub
	renderer *staterender.Renderer
	log      *slog.Logger
	opts     Options

	// logs holds the chunks agents sent in answer to a fetch, keyed by the
	// command id the API is waiting on.
	logsMu sync.Mutex
	logs   map[string]*logResult
}

type logResult struct {
	done chan struct{}
	text strings.Builder
	core nodepb.Core
}

// New returns a server.
func New(st *store.Store, box *secret.Box, ca *CAManager, hub *Hub, renderer *staterender.Renderer, log *slog.Logger, opts Options) *Server {
	if log == nil {
		log = slog.Default()
	}
	if opts.AgentCertTTL <= 0 {
		opts.AgentCertTTL = 365 * 24 * time.Hour
	}
	if opts.LogBuffer <= 0 {
		opts.LogBuffer = 1 << 20
	}
	return &Server{
		store:    st,
		box:      box,
		ca:       ca,
		hub:      hub,
		renderer: renderer,
		log:      log,
		opts:     opts,
		logs:     map[string]*logResult{},
	}
}

// Listen starts the gRPC server.
//
// The TLS configuration asks for a client certificate but verifies it by hand,
// because Register is called before an agent has one. Every method on
// NodeControl checks for a verified chain itself, so there is no path where an
// unauthenticated connection reaches node data.
func (s *Server) Listen(ctx context.Context, address string) (*grpc.Server, net.Listener, error) {
	ca, err := s.ca.Ensure(ctx)
	if err != nil {
		return nil, nil, err
	}
	certPEM, keyPEM, err := s.ca.ServerCertificate(ctx, s.opts.Hosts)
	if err != nil {
		return nil, nil, err
	}
	// The CA is appended to the server's chain on purpose. An agent enrolling
	// for the first time has only the fingerprint from its install command,
	// and it pins the CA, not the leaf - so the CA has to be on the wire for
	// it to have anything to check against.
	chainPEM := append(append([]byte(nil), certPEM...), ca.CertPEM()...)
	cert, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("noderpc: server key pair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		return nil, nil, errors.New("noderpc: the CA certificate could not be used")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		// Not RequireAndVerifyClientCert: enrolment happens over this same
		// listener, before the agent has a certificate. Each NodeControl
		// method insists on a verified chain.
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS13,
	}

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		// Keepalives are what notice a node that vanished without closing
		// its stream, which is most of them.
		grpc.KeepaliveParams(keepaliveParams()),
		grpc.KeepaliveEnforcementPolicy(keepalivePolicy()),
	)
	nodepb.RegisterRegistrationServer(server, s)
	nodepb.RegisterNodeControlServer(server, s)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("noderpc: listen on %s: %w", address, err)
	}
	return server, listener, nil
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// Register turns a one-time token into a client certificate.
func (s *Server) Register(ctx context.Context, req *nodepb.RegisterRequest) (*nodepb.RegisterResponse, error) {
	if req.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "no enrolment token")
	}
	fromIP := clientIP(ctx)

	node, err := s.store.SpendNodeToken(ctx, req.GetToken(), fromIP)
	if err != nil {
		if errors.Is(err, store.ErrTokenSpent) {
			s.log.Warn("enrolment refused: token not usable", "ip", fromIP)
			// Deliberately vague: an agent cannot tell "already used" from
			// "never existed", so neither can someone guessing tokens.
			return nil, status.Error(codes.PermissionDenied, "the enrolment token is not usable")
		}
		s.log.Error("enrolment failed", "ip", fromIP, "error", err)
		return nil, status.Error(codes.Internal, "could not enrol")
	}

	resp, err := s.issueCertificate(ctx, node, req.GetCsrPem())
	if err != nil {
		return nil, err
	}

	// The host information is advisory - the address clients dial stays
	// whatever an admin configured - but recording it is what makes the node
	// list useful before the first heartbeat.
	if host := req.GetHost(); host != nil {
		if err := s.store.NodeConnected(ctx, node.ID,
			req.GetAgentVersion(), "", "", "", hostInfo(host)); err != nil {
			s.log.Warn("could not record host information", "node", node.UUID, "error", err)
		}
	}

	_ = s.store.RecordEvent(ctx, store.NewEvent{
		Severity: "info",
		Type:     "node_enrolled",
		NodeID:   &node.ID,
		Message:  fmt.Sprintf("node %s enrolled from %s", node.Name, fromIP),
		Details:  map[string]any{"agent_version": req.GetAgentVersion(), "ip": fromIP},
	})
	s.log.Info("node enrolled", "node", node.UUID, "name", node.Name, "ip", fromIP)
	return resp, nil
}

// RenewCertificate issues a fresh certificate to an already-enrolled agent.
func (s *Server) RenewCertificate(ctx context.Context, req *nodepb.RenewCertificateRequest) (*nodepb.RegisterResponse, error) {
	node, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := s.issueCertificate(ctx, node, req.GetCsrPem())
	if err != nil {
		return nil, err
	}
	s.log.Info("certificate renewed", "node", node.UUID)
	return resp, nil
}

// issueCertificate signs a CSR for a node and records the result.
func (s *Server) issueCertificate(ctx context.Context, node *store.Node, csrPEM []byte) (*nodepb.RegisterResponse, error) {
	ca, err := s.ca.Ensure(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "the certificate authority is unavailable")
	}
	issued, err := ca.SignAgent(csrPEM, node.UUID, s.opts.AgentCertTTL)
	if err != nil {
		// A bad CSR is the agent's fault, so say which.
		return nil, status.Errorf(codes.InvalidArgument, "certificate request: %v", err)
	}

	fingerprint, err := decodeHex(issued.Fingerprint)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not record the certificate")
	}
	if err := s.store.RecordNodeCert(ctx, node.ID, issued.Serial, fingerprint,
		string(issued.CertPEM), issued.NotBefore, issued.NotAfter); err != nil {
		return nil, status.Error(codes.Internal, "could not record the certificate")
	}

	return &nodepb.RegisterResponse{
		NodeUuid:      node.UUID,
		ClientCertPem: issued.CertPEM,
		CaCertPem:     ca.CertPEM(),
		NotAfter:      timestamppb.New(issued.NotAfter),
	}, nil
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// authenticate resolves the node a connection belongs to.
//
// The node's identity comes from the certificate's common name, not from
// anything the agent says, so there is no "which node are you" message to
// forge. The certificate's fingerprint is also checked against the revocation
// list, which is how a node is cut off before its certificate expires.
func (s *Server) authenticate(ctx context.Context) (*store.Node, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer information")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "the connection is not TLS")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, status.Error(codes.Unauthenticated, "a client certificate is required")
	}
	cert := tlsInfo.State.VerifiedChains[0][0]

	nodeUUID := nodeca.NodeUUIDFromCommonName(cert)
	if nodeUUID == "" {
		return nil, status.Error(codes.Unauthenticated, "the client certificate names no node")
	}

	sum := sha256.Sum256(cert.Raw)
	revoked, err := s.store.CertRevoked(ctx, sum[:])
	if err != nil {
		return nil, status.Error(codes.Internal, "could not check the certificate")
	}
	if revoked {
		s.log.Warn("refused a revoked certificate", "node", nodeUUID)
		return nil, status.Error(codes.PermissionDenied, "this certificate has been revoked")
	}

	node, err := s.store.NodeByUUID(ctx, nodeUUID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The node was deleted while its agent was away.
			return nil, status.Error(codes.PermissionDenied, "this node no longer exists")
		}
		return nil, status.Error(codes.Internal, "could not read the node")
	}
	return node, nil
}

func clientIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

func hostInfo(h *nodepb.HostInfo) store.NodeHost {
	return store.NodeHost{
		Hostname:      h.GetHostname(),
		OS:            h.GetOs(),
		Arch:          h.GetArch(),
		CPUCores:      h.GetCpuCores(),
		MemTotalBytes: h.GetMemTotalBytes(),
	}
}

func decodeHex(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var hi, lo byte
		var err error
		if hi, err = hexNibble(s[i*2]); err != nil {
			return nil, err
		}
		if lo, err = hexNibble(s[i*2+1]); err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("noderpc: %q is not hex", string(c))
	}
}

// marshalState is used by the API when it wants to store a snapshot.
func marshalState(state *nodepb.NodeState) ([]byte, error) {
	raw, err := proto.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("noderpc: marshal state: %w", err)
	}
	return raw, nil
}

// CAFingerprint returns the node CA's SHA-256, which install commands pin so
// an agent can verify the panel before it trusts anything it is sent.
func (s *Server) CAFingerprint(ctx context.Context) (string, error) {
	return s.ca.Fingerprint(ctx)
}

// CACertPEM returns the node CA certificate.
func (s *Server) CACertPEM(ctx context.Context) ([]byte, error) {
	return s.ca.CertPEM(ctx)
}

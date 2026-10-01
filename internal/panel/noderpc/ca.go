// Package noderpc is Main's side of the agent protocol: enrolment, the
// session stream, and the hub that lets the rest of the panel reach a
// connected node.
package noderpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/nodeca"
	"github.com/thehavlok/whitenet/internal/panel/secret"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

// CALifetime is how long the node CA is valid. It is long because every agent
// certificate is capped by it, and rotating it means re-enrolling the fleet.
const CALifetime = 10 * 365 * 24 * time.Hour

// CAManager owns the node CA: it loads it from the database or creates it on
// first start, and keeps it in memory for signing.
type CAManager struct {
	store *store.Store
	box   *secret.Box

	mu sync.RWMutex
	ca *nodeca.CA
}

// NewCAManager returns a manager. Nothing is loaded until Ensure is called.
func NewCAManager(st *store.Store, box *secret.Box) *CAManager {
	return &CAManager{store: st, box: box}
}

// Ensure loads the CA, creating it if the panel has never had one.
//
// The private key is stored encrypted with the panel's master key. Losing the
// master key therefore means losing the CA, which means re-enrolling every
// node - which is why the master key is the one thing the README says to back
// up.
func (m *CAManager) Ensure(ctx context.Context) (*nodeca.CA, error) {
	m.mu.RLock()
	if m.ca != nil {
		defer m.mu.RUnlock()
		return m.ca, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	// Another caller may have loaded it while this one waited.
	if m.ca != nil {
		return m.ca, nil
	}

	stored, err := m.store.LoadCA(ctx, store.SettingCAName)
	if err != nil {
		return nil, err
	}
	if stored != nil {
		keyPEM, err := m.box.Open(stored.KeyPEM)
		if err != nil {
			// Almost always the wrong master key, so say so rather than
			// leaving an operator to work out what "decrypt failed" means.
			return nil, fmt.Errorf("noderpc: could not decrypt the node CA key; is the master key the same one the panel was set up with? %w", err)
		}
		ca, err := nodeca.Load([]byte(stored.CertPEM), keyPEM)
		if err != nil {
			return nil, err
		}
		m.ca = ca
		return ca, nil
	}

	ca, err := nodeca.NewCA(CALifetime)
	if err != nil {
		return nil, err
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		return nil, err
	}
	sealed, err := m.box.Seal(keyPEM)
	if err != nil {
		return nil, err
	}
	if err := m.store.SaveCA(ctx, store.SettingCAName, string(ca.CertPEM()), sealed, ca.NotAfter()); err != nil {
		return nil, err
	}
	m.ca = ca
	return ca, nil
}

// CertPEM returns the CA certificate, which install commands pin by
// fingerprint and agents store.
func (m *CAManager) CertPEM(ctx context.Context) ([]byte, error) {
	ca, err := m.Ensure(ctx)
	if err != nil {
		return nil, err
	}
	return ca.CertPEM(), nil
}

// Fingerprint returns the CA's SHA-256, which goes into the install command.
func (m *CAManager) Fingerprint(ctx context.Context) (string, error) {
	ca, err := m.Ensure(ctx)
	if err != nil {
		return "", err
	}
	return ca.Fingerprint(), nil
}

// ServerCertificate issues the certificate Main presents to agents.
//
// Agents verify it against the pinned CA rather than against public trust, so
// the names only have to cover however the panel is actually reached -
// including a bare IP, which no public CA would issue for.
func (m *CAManager) ServerCertificate(ctx context.Context, hosts []string) (certPEM, keyPEM []byte, err error) {
	ca, err := m.Ensure(ctx)
	if err != nil {
		return nil, nil, err
	}
	// A year: short enough that a leaked key stops working, long enough that
	// nobody has to think about it between upgrades.
	return ca.SignServer(hosts, 365*24*time.Hour)
}

package subhttp

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/thehavlok/whitenet/internal/panel/sharelink"
	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

// ChannelShareLink builds a self-contained whitenet:// link for one flux
// channel: the secret and the carriers travel in the link, so whoever imports
// it connects straight to this channel without a subscription token or a
// lease.
//
// This is the "share a config with someone" case, as opposed to a
// subscription, which is tied to a user and leases a channel from the pool.
// Because the channel is embedded, it is effectively dedicated to whoever
// holds the link - the same credential two people share is the same one
// client, which is all a flux channel carries anyway.
func (s *Server) ChannelShareLink(r *http.Request, channelID uint64) (string, error) {
	channel, err := s.store.ChannelByID(r.Context(), channelID)
	if err != nil {
		return "", err
	}
	if !channel.Enabled {
		return "", errors.New("the channel is disabled, so a link to it would not connect")
	}

	node, err := s.store.NodeByID(r.Context(), channel.NodeID)
	if err != nil {
		return "", err
	}

	cfg, err := s.store.NodeOpenFluxConfig(r.Context(), node.ID)
	if err != nil {
		return "", err
	}
	mode := "l4"
	if cfg != nil && cfg.Mode != "" {
		mode = cfg.Mode
	}

	secretValue, err := s.box.OpenString(channel.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("decrypt the channel secret: %w", err)
	}
	carriers, err := s.carriers(channel, node)
	if err != nil {
		return "", err
	}

	server := subscription.Server{
		ID:        node.UUID + ":" + channel.UUID,
		Name:      fluxName(node, channel.Transport),
		Country:   node.Country(),
		Protocol:  subscription.ProtocolFlux,
		Transport: channel.Transport,
		Flux: &subscription.Flux{
			Mode: mode,
			Channels: []subscription.Channel{{
				ID:       channel.UUID,
				Secret:   secretValue,
				Context:  channel.SessionContext.String,
				Carriers: carriers,
			}},
		},
	}

	branding, err := s.store.Branding(r.Context())
	if err != nil {
		return "", err
	}

	bundle := sharelink.Bundle{
		Name:     server.Name,
		Servers:  []subscription.Server{server},
		Branding: brandingResponse(branding),
	}
	return sharelink.Encode(bundle)
}

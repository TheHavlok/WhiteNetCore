package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/keygen"
	"github.com/thehavlok/whitenet/internal/panel/sharelink"
	"github.com/thehavlok/whitenet/internal/panel/store"
)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	filter := store.UserFilter{
		Search: strings.TrimSpace(r.URL.Query().Get("search")),
		Status: r.URL.Query().Get("status"),
		Limit:  queryInt(r, "limit", 50),
		Offset: queryInt(r, "offset", 0),
	}
	if filter.Limit < 1 || filter.Limit > 500 {
		filter.Limit = 50
	}
	if groupID := queryInt(r, "group_id", 0); groupID > 0 {
		filter.GroupID = uint64(groupID)
	}
	if days := queryInt(r, "expiring_in_days", 0); days > 0 {
		filter.ExpiringWithin = time.Duration(days) * 24 * time.Hour
	}

	users, total, err := s.store.ListUsers(r.Context(), filter)
	if err != nil {
		s.writeStoreError(w, err, "the users")
		return
	}
	out := make([]map[string]any, 0, len(users))
	for i := range users {
		groups, err := s.store.UserGroupIDs(r.Context(), users[i].ID)
		if err != nil {
			s.writeStoreError(w, err, "the user's groups")
			return
		}
		out = append(out, s.userResponse(r, &users[i], groups, 0))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"users":  out,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the user")
		return
	}
	groups, err := s.store.UserGroupIDs(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the user's groups")
		return
	}
	devices, err := s.store.UserDevices(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the devices")
		return
	}
	s.writeJSON(w, http.StatusOK, s.userResponse(r, user, groups, len(devices)))
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string     `json:"name"`
		Comment       string     `json:"comment"`
		ExpiresAt     *time.Time `json:"expires_at"`
		ValidDays     int        `json:"valid_days"`
		TrafficLimit  uint64     `json:"traffic_limit"`
		DevicesLimit  uint32     `json:"devices_limit"`
		ResetStrategy string     `json:"reset_strategy"`
		GroupIDs      []uint64   `json:"group_ids"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		s.writeFieldError(w, codeBadRequest, "name", "a user needs a name")
		return
	}

	// Anything the form left empty comes from the settings, which is what
	// makes creating a user one field in the common case.
	defaults, err := s.store.UserDefaults(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "the defaults")
		return
	}
	if req.TrafficLimit == 0 {
		req.TrafficLimit = defaults.TrafficLimitBytes
	}
	if req.DevicesLimit == 0 {
		req.DevicesLimit = defaults.DevicesLimit
	}
	if len(req.GroupIDs) == 0 {
		req.GroupIDs = defaults.GroupIDs
	}
	expiresAt := req.ExpiresAt
	if expiresAt == nil {
		days := req.ValidDays
		if days == 0 {
			days = defaults.ValidDays
		}
		if days > 0 {
			when := time.Now().UTC().AddDate(0, 0, days)
			expiresAt = &when
		}
	}

	// One identity per user across every protocol, so their configuration
	// does not change as nodes come and go.
	password, err := keygen.NewPassword()
	if err != nil {
		s.writeStoreError(w, err, "the credentials")
		return
	}
	// A 2022 Shadowsocks user key is base64 of 32 bytes, which also serves as
	// a perfectly good legacy password.
	ssPassword, err := keygen.NewShadowsocks2022Key("2022-blake3-aes-256-gcm")
	if err != nil {
		s.writeStoreError(w, err, "the credentials")
		return
	}
	sealedPassword, err := s.box.SealString(password)
	if err != nil {
		s.writeStoreError(w, err, "the credentials")
		return
	}
	sealedSS, err := s.box.SealString(ssPassword)
	if err != nil {
		s.writeStoreError(w, err, "the credentials")
		return
	}

	user, err := s.store.CreateUser(r.Context(), store.NewUser{
		Name:          req.Name,
		Comment:       req.Comment,
		VLESSUUID:     keygen.NewUUID(),
		Password:      sealedPassword,
		SSPassword:    sealedSS,
		ExpiresAt:     expiresAt,
		TrafficLimit:  req.TrafficLimit,
		DevicesLimit:  req.DevicesLimit,
		ResetStrategy: req.ResetStrategy,
		GroupIDs:      req.GroupIDs,
	})
	if err != nil {
		s.writeStoreError(w, err, "the user")
		return
	}

	// Every node in the user's groups now has one more user to serve.
	s.pushStateToAll(r)
	s.audit(r, "user.create", "user", user.UUID, map[string]any{"name": user.Name})
	s.writeJSON(w, http.StatusCreated, s.userResponse(r, user, req.GroupIDs, 0))
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Name          *string    `json:"name"`
		Comment       *string    `json:"comment"`
		ExpiresAt     *time.Time `json:"expires_at"`
		ClearExpiry   bool       `json:"clear_expiry"`
		TrafficLimit  *uint64    `json:"traffic_limit"`
		DevicesLimit  *uint32    `json:"devices_limit"`
		ResetStrategy *string    `json:"reset_strategy"`
		Status        *string    `json:"status"`
		GroupIDs      *[]uint64  `json:"group_ids"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	if req.Status != nil && !validUserStatus(*req.Status) {
		s.writeFieldError(w, codeBadRequest, "status",
			"status must be active, disabled, expired or limited")
		return
	}

	update := store.UserUpdate{
		Name:          req.Name,
		Comment:       req.Comment,
		TrafficLimit:  req.TrafficLimit,
		DevicesLimit:  req.DevicesLimit,
		ResetStrategy: req.ResetStrategy,
		Status:        req.Status,
		GroupIDs:      req.GroupIDs,
	}
	// Two different intentions: "never expires" and "expires then". A nil
	// pointer means neither was expressed.
	switch {
	case req.ClearExpiry:
		var never *time.Time
		update.ExpiresAt = &never
	case req.ExpiresAt != nil:
		when := req.ExpiresAt.UTC()
		pointer := &when
		update.ExpiresAt = &pointer
	}

	user, err := s.store.UpdateUser(r.Context(), id, update)
	if err != nil {
		s.writeStoreError(w, err, "the user")
		return
	}
	// A user who is no longer active must lose their flux channel too, or
	// they keep holding a slot in the pool.
	if req.Status != nil && *req.Status != store.UserActive {
		if err := s.store.RevokeUserLeases(r.Context(), id); err != nil {
			s.log.Warn("could not release the user's leases", "user", id, "error", err)
		}
	}
	s.pushStateToAll(r)

	groups, _ := s.store.UserGroupIDs(r.Context(), id)
	s.audit(r, "user.update", "user", user.UUID, nil)
	s.writeJSON(w, http.StatusOK, s.userResponse(r, user, groups, 0))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the user")
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		s.writeStoreError(w, err, "the user")
		return
	}
	s.pushStateToAll(r)
	s.audit(r, "user.delete", "user", user.UUID, map[string]any{"name": user.Name})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleReissueToken replaces a user's subscription token, which is how a
// leaked link is revoked: the old one stops working at once.
func (s *Server) handleReissueToken(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the user")
		return
	}
	token, err := s.store.ReissueSubToken(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the subscription token")
		return
	}
	s.audit(r, "user.reissue_token", "user", user.UUID, nil)

	links, err := s.subscriptionLinks(r, token)
	if err != nil {
		s.writeStoreError(w, err, "the subscription link")
		return
	}
	s.writeJSON(w, http.StatusOK, links)
}

func (s *Server) handleResetTraffic(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the user")
		return
	}
	if err := s.store.ResetUserTraffic(r.Context(), id); err != nil {
		s.writeStoreError(w, err, "the traffic")
		return
	}
	// A user who was over their limit is usable again, so the nodes need to
	// hear about it.
	s.pushStateToAll(r)
	s.audit(r, "user.reset_traffic", "user", user.UUID,
		map[string]any{"was": user.TrafficUsed})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	devices, err := s.store.UserDevices(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the devices")
		return
	}
	out := make([]map[string]any, 0, len(devices))
	for _, device := range devices {
		out = append(out, map[string]any{
			"id":            device.ID,
			"hwid":          device.HWID,
			"model":         device.Model.String,
			"platform":      device.Platform.String,
			"app_version":   device.AppVersion.String,
			"first_seen_at": device.FirstSeenAt,
			"last_seen_at":  device.LastSeenAt,
			"last_ip":       device.LastIP.String,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	deviceID, ok := s.pathID(w, r, "deviceID")
	if !ok {
		return
	}
	if err := s.store.DeleteDevice(r.Context(), userID, deviceID); err != nil {
		s.writeStoreError(w, err, "the device")
		return
	}
	s.audit(r, "user.delete_device", "user", fmt.Sprint(userID),
		map[string]any{"device_id": deviceID})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleUserTraffic(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	points, err := s.store.UserTrafficHistory(r.Context(), id, queryInt(r, "days", 30))
	if err != nil {
		s.writeStoreError(w, err, "the traffic")
		return
	}
	out := make([]map[string]any, 0, len(points))
	for _, point := range points {
		out = append(out, map[string]any{
			"day":      point.Day.Format("2006-01-02"),
			"uplink":   point.UplinkBytes,
			"downlink": point.DownlinkBytes,
			"total":    point.UplinkBytes + point.DownlinkBytes,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"days": out})
}

// handleUserSubscription returns the user's links and a QR code, which is what
// the copy-and-scan buttons in the UI use.
func (s *Server) handleUserSubscription(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "the user")
		return
	}
	links, err := s.subscriptionLinks(r, user.SubToken)
	if err != nil {
		s.writeStoreError(w, err, "the subscription link")
		return
	}
	s.writeJSON(w, http.StatusOK, links)
}

// subscriptionLinks assembles the URL, the deep link and the QR code.
func (s *Server) subscriptionLinks(r *http.Request, token string) (map[string]any, error) {
	domains, err := s.store.Domains(r.Context())
	if err != nil {
		return nil, err
	}
	base := domains.SubBaseURL
	if base == "" {
		base = domains.PanelURL
	}
	if base == "" {
		base = requestBaseURL(r)
	}
	subURL := strings.TrimRight(base, "/") + "/sub/" + token

	out := map[string]any{"url": subURL, "token": token}

	// The import deep link needs https, which a local test panel may not
	// have; the URL itself is still useful, so this is not an error.
	if deepLink, err := sharelink.ImportLink(subURL); err == nil {
		out["deep_link"] = deepLink
		if png, err := sharelink.PNG(deepLink, 320); err == nil {
			out["qr_png_base64"] = base64PNG(png)
		}
	} else {
		out["deep_link_error"] = err.Error()
	}
	return out, nil
}

func (s *Server) handleBulkUsers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserIDs    []uint64  `json:"user_ids"`
		Action     string    `json:"action"`
		ExtendDays int       `json:"extend_days"`
		Status     string    `json:"status"`
		GroupIDs   *[]uint64 `json:"group_ids"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	if len(req.UserIDs) == 0 {
		s.writeFieldError(w, codeBadRequest, "user_ids", "select at least one user")
		return
	}
	if len(req.UserIDs) > 5000 {
		s.writeFieldError(w, codeBadRequest, "user_ids", "at most 5000 users at a time")
		return
	}

	action := store.BulkUserAction{UserIDs: req.UserIDs}
	switch req.Action {
	case "extend":
		if req.ExtendDays <= 0 {
			s.writeFieldError(w, codeBadRequest, "extend_days", "extend_days must be positive")
			return
		}
		action.ExtendBy = time.Duration(req.ExtendDays) * 24 * time.Hour
	case "disable":
		action.SetStatus = store.UserDisabled
	case "enable":
		action.SetStatus = store.UserActive
	case "set_status":
		if !validUserStatus(req.Status) {
			s.writeFieldError(w, codeBadRequest, "status", "unknown status "+req.Status)
			return
		}
		action.SetStatus = req.Status
	case "set_groups":
		if req.GroupIDs == nil {
			s.writeFieldError(w, codeBadRequest, "group_ids", "group_ids is required for set_groups")
			return
		}
		action.SetGroupIDs = req.GroupIDs
	case "reset_traffic":
		action.ResetTraffic = true
	case "delete":
		action.Delete = true
	default:
		s.writeFieldError(w, codeBadRequest, "action",
			"action must be extend, enable, disable, set_status, set_groups, reset_traffic or delete")
		return
	}

	affected, err := s.store.ApplyBulkUserAction(r.Context(), action)
	if err != nil {
		s.writeStoreError(w, err, "the users")
		return
	}
	// Disabling or deleting users must also free the flux channels they hold.
	if action.Delete || action.SetStatus == store.UserDisabled {
		for _, userID := range req.UserIDs {
			if err := s.store.RevokeUserLeases(r.Context(), userID); err != nil {
				s.log.Warn("could not release a user's leases", "user", userID, "error", err)
			}
		}
	}
	s.pushStateToAll(r)

	s.audit(r, "user.bulk_"+req.Action, "user", "",
		map[string]any{"count": affected, "user_ids": req.UserIDs})
	s.writeJSON(w, http.StatusOK, map[string]any{"affected": affected})
}

func (s *Server) userResponse(r *http.Request, user *store.User, groupIDs []uint64, deviceCount int) map[string]any {
	if groupIDs == nil {
		groupIDs = []uint64{}
	}
	out := map[string]any{
		"id":                user.ID,
		"uuid":              user.UUID,
		"name":              user.Name,
		"comment":           user.Comment.String,
		"status":            user.Status,
		"expires_at":        nullTime(user.ExpiresAt),
		"traffic_limit":     user.TrafficLimit,
		"traffic_used":      user.TrafficUsed,
		"devices_limit":     user.DevicesLimit,
		"devices_used":      deviceCount,
		"reset_strategy":    user.ResetStrategy,
		"last_reset_at":     nullTime(user.LastResetAt),
		"last_sub_fetch_at": nullTime(user.LastSubFetchAt),
		"group_ids":         groupIDs,
		"created_at":        user.CreatedAt,
		// The token is shown so the UI can offer "copy link" without a second
		// request. It is a bearer credential, which is why only an
		// authenticated admin sees it.
		"sub_token": user.SubToken,
	}
	if user.TrafficLimit > 0 {
		out["traffic_remaining"] = int64(user.TrafficLimit) - int64(user.TrafficUsed)
	} else {
		out["traffic_remaining"] = nil
	}
	if user.ExpiresAt.Valid {
		out["days_remaining"] = int(time.Until(user.ExpiresAt.Time).Hours() / 24)
	} else {
		out["days_remaining"] = nil
	}
	return out
}

func validUserStatus(status string) bool {
	switch status {
	case store.UserActive, store.UserDisabled, store.UserExpired, store.UserLimited:
		return true
	default:
		return false
	}
}

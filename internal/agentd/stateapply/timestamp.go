package stateapply

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// timestamp converts a Go time for the protocol. It exists so the conversion
// is in one place rather than spelled out at every call site.
func timestamp(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t.UTC())
}

package main

import (
	"context"
	"fmt"

	"github.com/thehavlok/whitenet/internal/auth"
	"github.com/thehavlok/whitenet/internal/auth/wbstream"
)

func main() {
	roomID := "test_u6nxcf32"
	key := "d823fa01cb3e0609b67322f7cf984c4ee2e4ce2e294936fc24ef38c9e59f4799"
	p := wbstream.NewProvider(nil)
	cfg := auth.Config{
		Mode: auth.ModeGuest,
		Room: roomID,
		Key:  key,
	}

	res, err := p.Issue(context.Background(), cfg)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Success! Token: %s\n", res.Token)
	}
}

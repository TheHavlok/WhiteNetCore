package main

import (
	"context"
	"fmt"
	"github.com/thehavlok/whitenet/internal/auth"
	"github.com/thehavlok/whitenet/internal/auth/wbstream"
)

func main() {
	p := wbstream.Provider{}
	
	// Test 1: empty name (like server)
	fmt.Println("Testing empty name...")
	_, err := p.Issue(context.Background(), auth.Config{
		Name: "",
		RoomURL: "019e83ef-a2eb-79c8-b590-ba85bb6a34ee",
	})
	fmt.Printf("Empty name error: %v\n", err)

	// Test 2: ios-client name
	fmt.Println("Testing ios-client name...")
	_, err = p.Issue(context.Background(), auth.Config{
		Name: "ios-client-123",
		RoomURL: "019e83ef-a2eb-79c8-b590-ba85bb6a34ee",
	})
	fmt.Printf("ios-client name error: %v\n", err)
}

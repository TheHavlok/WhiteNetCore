package main

import (
	"context"
	"fmt"

	"github.com/thehavlok/whitenet/internal/auth"
	"github.com/thehavlok/whitenet/internal/auth/wbstream"
)

func main() {
	roomID := "019e83fd-895b-7ea8-af49-bd339de8af6f"
	p := wbstream.Provider{}

	fmt.Println("Testing room:", roomID)
	_, err := p.Issue(context.Background(), auth.Config{RoomURL: roomID, Name: "blue_fox_42"})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Success!")
	}
}

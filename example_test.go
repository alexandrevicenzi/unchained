package unchained_test

import (
	"fmt"

	"github.com/alexandrevicenzi/unchained"
)

func ExampleCheckPassword() {
	valid, err := unchained.CheckPassword("admin", "pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")

	if valid {
		fmt.Println("Password is valid.")
	} else {
		if err == nil {
			fmt.Println("Password is valid.")
		} else {
			fmt.Printf("Error decoding password: %s\n", err)
		}
	}
}

func ExampleMakePassword() {
	hash, err := unchained.MakePassword("my-password", unchained.GetRandomString(12), "default")

	if err == nil {
		fmt.Println(hash)
	} else {
		fmt.Printf("Error encoding password: %s\n", err)
	}
}

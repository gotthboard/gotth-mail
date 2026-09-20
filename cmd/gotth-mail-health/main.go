package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/version"
)

var role = "invalid"

var rolePorts = map[string][]string{
	"control-plane": {"127.0.0.1:8080"},
	"front":         {"127.0.0.1:1025", "127.0.0.1:1465", "127.0.0.1:1587", "127.0.0.1:1143", "127.0.0.1:1993"},
	"postfix":       {"127.0.0.1:25", "127.0.0.1:10026"},
	"dovecot":       {"127.0.0.1:143", "127.0.0.1:24", "127.0.0.1:12345"},
	"rspamd":        {"127.0.0.1:11332"},
}

func main() {
	if err := validateBuildIdentity(version.Version); err != nil {
		fmt.Fprintln(os.Stderr, "gotth-mail health: invalid build identity")
		os.Exit(2)
	}
	if len(os.Args) != 2 || os.Args[1] != role {
		fmt.Fprintln(os.Stderr, "gotth-mail health: role mismatch")
		os.Exit(2)
	}
	ports, ok := rolePorts[role]
	if !ok {
		fmt.Fprintln(os.Stderr, "gotth-mail health: invalid compiled role")
		os.Exit(2)
	}
	for _, address := range ports {
		connection, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gotth-mail health: service unavailable")
			os.Exit(1)
		}
		connection.Close()
	}
}

func validateBuildIdentity(value string) error {
	return version.Validate(value)
}

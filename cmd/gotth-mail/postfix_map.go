package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/daemon"
)

type postfixMapKind uint8

const (
	postfixDomainMap postfixMapKind = iota + 1
	postfixMailboxMap
	postfixAliasMap
)

// servePostfixMap accepts an unbounded request stream on an already-bound
// required listener. Per accepted connection, time and auxiliary space are
// O(1), Omega(1), tight Theta(1), excluding the delegated request handler.
func servePostfixMap(listener net.Listener, kind postfixMapKind, service daemon.Service) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Fatalf("Postfix map accept failed: %v", err)
		}
		go handlePostfixMap(connection, kind, service)
	}
}

func handlePostfixMap(connection net.Conn, kind postfixMapKind, service daemon.Service) {
	defer connection.Close()
	scanner := bufio.NewScanner(connection)
	scanner.Buffer(make([]byte, 1024), 4096)
	writer := bufio.NewWriter(connection)
	defer writer.Flush()
	for scanner.Scan() {
		line := scanner.Text()
		encoded, found := strings.CutPrefix(line, "get ")
		key, err := url.PathUnescape(encoded)
		if !found || err != nil || key == "" || len(key) > 320 || strings.ContainsAny(key, "\x00\r\n") {
			_, _ = fmt.Fprint(writer, "400 malformed request\n")
			_ = writer.Flush()
			continue
		}
		response := lookupPostfixMap(kind, service, key)
		_, _ = fmt.Fprint(writer, response)
		_ = writer.Flush()
	}
}

func lookupPostfixMap(kind postfixMapKind, service daemon.Service, key string) string {
	correlationID := "postfix-map"
	var response daemon.Response
	switch kind {
	case postfixDomainMap:
		response = service.PostfixDomain(correlationID, key)
	case postfixMailboxMap:
		response = service.PostfixMailbox(correlationID, key)
	case postfixAliasMap:
		response = service.PostfixAlias(correlationID, key)
	default:
		return "400 unsupported map\n"
	}
	switch response.Decision {
	case daemon.OK:
		value := "1"
		if kind == postfixAliasMap {
			value = strings.Join(response.Targets, ",")
			if value == "" {
				return "500 not found\n"
			}
		}
		return "200 " + url.PathEscape(value) + "\n"
	case daemon.NotFound, daemon.Reject:
		return "500 not found\n"
	default:
		return "400 temporary lookup failure\n"
	}
}

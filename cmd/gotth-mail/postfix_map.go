package main

import (
	"bufio"
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

func servePostfixMap(address string, kind postfixMapKind, service daemon.Service) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Printf("Postfix map listen failed: %v", err)
		return
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("Postfix map accept failed: %v", err)
			continue
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

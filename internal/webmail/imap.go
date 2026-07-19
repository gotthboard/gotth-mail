package webmail

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type NetIMAPClient struct {
	Addr     string
	Username string
	Password string
	Timeout  time.Duration
}

func (c NetIMAPClient) ListFolders(ctx context.Context, user string) ([]string, error) {
	ic, err := c.connect(ctx, user)
	if err != nil {
		return nil, err
	}
	defer ic.close()
	lines, err := ic.cmd(`LIST "" "*"`)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "* LIST ") {
			continue
		}
		name := imapMailboxName(line)
		if name != "" && name != "." {
			out = append(out, name)
		}
	}
	if !hasFolder(out, "INBOX") {
		out = append(out, "INBOX")
	}
	sort.Strings(out)
	return out, nil
}

func (c NetIMAPClient) ListMessages(ctx context.Context, user, folder, cursor string, limit int) ([]Message, error) {
	ic, err := c.connect(ctx, user)
	if err != nil {
		return nil, err
	}
	defer ic.close()
	ids, err := ic.messageIDs(folder, "ALL")
	if err != nil {
		return nil, err
	}
	ids = afterCursor(ids, cursor)
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]Message, 0, len(ids))
	for _, id := range ids {
		msg, err := ic.fetchMessage(folder, id)
		if err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	return out, nil
}

func (c NetIMAPClient) ReadMessage(ctx context.Context, user, folder, id string) (Message, error) {
	ic, err := c.connect(ctx, user)
	if err != nil {
		return Message{}, err
	}
	defer ic.close()
	return ic.fetchMessage(folder, id)
}

func (c NetIMAPClient) Search(ctx context.Context, user, folder, query, cursor string, limit int) ([]Message, error) {
	ic, err := c.connect(ctx, user)
	if err != nil {
		return nil, err
	}
	defer ic.close()
	ids, err := ic.messageIDs(folder, `TEXT `+imapQuote(query))
	if err != nil {
		return nil, err
	}
	ids = afterCursor(ids, cursor)
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]Message, 0, len(ids))
	for _, id := range ids {
		msg, err := ic.fetchMessage(folder, id)
		if err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	return out, nil
}

func (c NetIMAPClient) Quota(ctx context.Context) (int64, int64, error) { return 0, 0, nil }

func (c NetIMAPClient) connect(ctx context.Context, user string) (*imapConn, error) {
	addr := strings.TrimSpace(c.Addr)
	if addr == "" {
		return nil, errors.New("imap address required")
	}
	username := strings.TrimSpace(c.Username)
	if username == "" {
		username = strings.TrimSpace(user)
	}
	if username == "" || strings.ContainsAny(username, "\r\n") {
		return nil, errors.New("imap username required")
	}
	if c.Password == "" || strings.ContainsAny(c.Password, "\r\n") {
		return nil, errors.New("imap password required")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	ic := &imapConn{conn: conn, r: bufio.NewReader(conn)}
	greeting, err := ic.readLine()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.HasPrefix(greeting, "* OK") {
		conn.Close()
		return nil, fmt.Errorf("imap bad greeting: %s", greeting)
	}
	if _, err := ic.cmd("LOGIN " + imapQuote(username) + " " + imapQuote(c.Password)); err != nil {
		conn.Close()
		return nil, err
	}
	return ic, nil
}

type imapConn struct {
	conn net.Conn
	r    *bufio.Reader
	seq  int
}

func (c *imapConn) close() { _, _ = c.cmd("LOGOUT"); _ = c.conn.Close() }

func (c *imapConn) cmd(command string) ([]string, error) {
	c.seq++
	tag := fmt.Sprintf("A%04d", c.seq)
	if _, err := fmt.Fprintf(c.conn, "%s %s\r\n", tag, command); err != nil {
		return nil, err
	}
	var lines []string
	for {
		line, err := c.readLineWithLiteral(&lines)
		if err != nil {
			return nil, err
		}
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, tag+" ") {
			if strings.Contains(line, " OK") || strings.HasPrefix(line, tag+" OK") {
				return lines, nil
			}
			return lines, fmt.Errorf("imap command failed: %s", line)
		}
	}
}

var literalSuffix = regexp.MustCompile(`\{([0-9]+)\}$`)

func (c *imapConn) readLineWithLiteral(lines *[]string) (string, error) {
	line, err := c.readLine()
	if err != nil {
		return "", err
	}
	m := literalSuffix.FindStringSubmatch(line)
	if len(m) != 2 {
		return line, nil
	}
	n, _ := strconv.Atoi(m[1])
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.r, buf); err != nil {
		return "", err
	}
	*lines = append(*lines, line, string(buf))
	return c.readLine()
}

func (c *imapConn) readLine() (string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *imapConn) messageIDs(folder, criteria string) ([]string, error) {
	if _, err := c.cmd("SELECT " + imapQuote(folder)); err != nil {
		return nil, err
	}
	lines, err := c.cmd("SEARCH " + criteria)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, line := range lines {
		if strings.HasPrefix(line, "* SEARCH") {
			for _, f := range strings.Fields(strings.TrimPrefix(line, "* SEARCH")) {
				ids = append(ids, f)
			}
		}
	}
	return ids, nil
}

func (c *imapConn) fetchMessage(folder, id string) (Message, error) {
	if strings.ContainsAny(id, " \r\n") || id == "" {
		return Message{}, errors.New("invalid imap message id")
	}
	if _, err := c.cmd("SELECT " + imapQuote(folder)); err != nil {
		return Message{}, err
	}
	lines, err := c.cmd("FETCH " + id + " BODY[]")
	if err != nil {
		return Message{}, err
	}
	var raw string
	for _, line := range lines {
		if strings.Contains(line, "\r\n") || strings.Contains(line, "Subject:") || strings.Contains(line, "From:") {
			raw = line
			break
		}
	}
	if raw == "" {
		return Message{}, errors.New("imap fetch returned no message body")
	}
	return ParseRawMessage(id, folder, []byte(raw))
}

func hasFolder(folders []string, want string) bool {
	for _, folder := range folders {
		if strings.EqualFold(folder, want) {
			return true
		}
	}
	return false
}

func afterCursor(ids []string, cursor string) []string {
	if cursor == "" {
		return ids
	}
	for i, id := range ids {
		if id == cursor {
			return ids[i+1:]
		}
	}
	return nil
}

func imapQuote(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return `"` + v + `"`
}

func imapMailboxName(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasSuffix(v, `"`) {
		end := len(v) - 1
		for i := end - 1; i >= 0; i-- {
			if v[i] == '"' && (i == 0 || v[i-1] != '\\') {
				name := v[i+1 : end]
				return strings.ReplaceAll(strings.ReplaceAll(name, `\"`, `"`), `\\`, `\`)
			}
		}
	}
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[len(fields)-1], `"`)
}

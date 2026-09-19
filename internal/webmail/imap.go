package webmail

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/mail"
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
	out, err := folderNames(lines)
	if err != nil {
		return nil, err
	}
	if !hasFolder(out, "INBOX") {
		out = append(out, "INBOX")
	}
	sort.Strings(out)
	return out, nil
}

func (c NetIMAPClient) ListFoldersDetailed(ctx context.Context, user string) ([]FolderInfo, error) {
	ic, err := c.connect(ctx, user)
	if err != nil {
		return nil, err
	}
	defer ic.close()
	lines, err := ic.cmd(`LIST "" "*"`)
	if err != nil {
		return nil, err
	}
	folders, err := folderNames(lines)
	if err != nil {
		return nil, err
	}
	if !hasFolder(folders, "INBOX") {
		folders = append(folders, "INBOX")
	}
	out := make([]FolderInfo, 0, len(folders))
	for _, folder := range folders {
		status, err := ic.cmd("STATUS " + imapQuote(folder) + " (UNSEEN)")
		if err != nil {
			return nil, err
		}
		unread := 0
		found := false
		for _, line := range status {
			match := imapUnseen.FindStringSubmatch(line)
			if len(match) != 2 {
				continue
			}
			value, parseErr := strconv.Atoi(match[1])
			if parseErr != nil || value < 0 || found {
				return nil, errors.New("invalid imap unread status")
			}
			unread, found = value, true
		}
		if !found {
			return nil, errors.New("imap unread status unavailable")
		}
		out = append(out, FolderInfo{Name: folder, Unread: unread})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
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
		msg, err := ic.fetchSelectedMessageSummary(folder, id)
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
		msg, err := ic.fetchSelectedMessageSummary(folder, id)
		if err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	return out, nil
}

func (c NetIMAPClient) Quota(ctx context.Context, user string) (int64, int64, error) {
	ic, err := c.connect(ctx, user)
	if err != nil {
		return 0, 0, err
	}
	defer ic.close()
	lines, err := ic.cmd(`GETQUOTAROOT "INBOX"`)
	if err != nil {
		return 0, 0, err
	}
	var used, limit int64
	found := false
	for _, line := range lines {
		match := quotaStorage.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		u, uerr := strconv.ParseInt(match[1], 10, 64)
		l, lerr := strconv.ParseInt(match[2], 10, 64)
		if uerr != nil || lerr != nil || u < 0 || l < 0 || u > (1<<63-1)/1024 || l > (1<<63-1)/1024 {
			return 0, 0, errors.New("invalid imap storage quota")
		}
		if found {
			return 0, 0, errors.New("ambiguous imap storage quota")
		}
		used, limit, found = u*1024, l*1024, true
	}
	if !found {
		return 0, 0, errors.New("imap storage quota unavailable")
	}
	return used, limit, nil
}

func (c NetIMAPClient) SetFlag(ctx context.Context, user, folder, id, flag string, enabled bool) error {
	if !validIMAPUID(id) {
		return errors.New("invalid imap message id")
	}
	canonical, ok := map[string]string{"seen": `\Seen`, "flagged": `\Flagged`}[strings.ToLower(strings.TrimSpace(flag))]
	if !ok {
		return errors.New("unsupported imap flag")
	}
	ic, err := c.connect(ctx, user)
	if err != nil {
		return err
	}
	defer ic.close()
	if _, err := ic.cmd("SELECT " + imapQuote(folder)); err != nil {
		return err
	}
	operation := "+FLAGS.SILENT"
	if !enabled {
		operation = "-FLAGS.SILENT"
	}
	_, err = ic.cmd("UID STORE " + id + " " + operation + " (" + canonical + ")")
	return err
}

func (c NetIMAPClient) Move(ctx context.Context, user, folder, id, destination string) error {
	if !validIMAPUID(id) || strings.TrimSpace(destination) == "" {
		return errors.New("valid imap message and destination required")
	}
	ic, err := c.connect(ctx, user)
	if err != nil {
		return err
	}
	defer ic.close()
	if _, err := ic.cmd("SELECT " + imapQuote(folder)); err != nil {
		return err
	}
	_, err = ic.cmd("UID MOVE " + id + " " + imapQuote(destination))
	return err
}

func (c NetIMAPClient) Delete(ctx context.Context, user, folder, id string) error {
	if !validIMAPUID(id) {
		return errors.New("invalid imap message id")
	}
	ic, err := c.connect(ctx, user)
	if err != nil {
		return err
	}
	defer ic.close()
	if _, err := ic.cmd("SELECT " + imapQuote(folder)); err != nil {
		return err
	}
	if _, err := ic.cmd("UID STORE " + id + ` +FLAGS.SILENT (\Deleted)`); err != nil {
		return err
	}
	_, err = ic.cmd("UID EXPUNGE " + id)
	return err
}

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
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[1], "OK") {
				return lines, nil
			}
			return lines, fmt.Errorf("imap command failed: %s", line)
		}
	}
}

var literalSuffix = regexp.MustCompile(`\{([0-9]+)\}$`)
var quotaStorage = regexp.MustCompile(`(?i)\bSTORAGE[[:space:]]+([0-9]+)[[:space:]]+([0-9]+)`)
var imapUnseen = regexp.MustCompile(`(?i)\bUNSEEN[[:space:]]+([0-9]+)`)

const maxIMAPLiteralBytes = maxMIMEHeaderBytes + maxMIMEBodyBytes + (maxMIMEPartBytes * 4)

func (c *imapConn) readLineWithLiteral(lines *[]string) (string, error) {
	line, err := c.readLine()
	if err != nil {
		return "", err
	}
	m := literalSuffix.FindStringSubmatch(line)
	if len(m) != 2 {
		return line, nil
	}
	n64, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || n64 < 0 || n64 > maxIMAPLiteralBytes {
		return "", errors.New("invalid or oversized imap literal")
	}
	n := int(n64)
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
	lines, err := c.cmd("UID SEARCH " + criteria)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, line := range lines {
		if strings.HasPrefix(line, "* SEARCH") {
			for _, f := range strings.Fields(strings.TrimPrefix(line, "* SEARCH")) {
				if !validIMAPUID(f) {
					return nil, errors.New("invalid imap search uid")
				}
				ids = append(ids, f)
			}
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		left, _ := strconv.ParseUint(ids[i], 10, 63)
		right, _ := strconv.ParseUint(ids[j], 10, 63)
		return left > right
	})
	return ids, nil
}

func (c *imapConn) fetchMessage(folder, id string) (Message, error) {
	if !validIMAPUID(id) {
		return Message{}, errors.New("invalid imap message id")
	}
	if _, err := c.cmd("SELECT " + imapQuote(folder)); err != nil {
		return Message{}, err
	}
	lines, err := c.cmd("UID FETCH " + id + " (FLAGS BODY[])")
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
	message, err := ParseRawMessage(id, folder, []byte(raw))
	if err != nil {
		return Message{}, err
	}
	for _, line := range lines {
		match := imapFlags.FindStringSubmatch(line)
		if len(match) == 2 {
			message.Flags = strings.Fields(match[1])
			break
		}
	}
	return message, nil
}

// fetchSelectedMessageSummary assumes messageIDs already selected folder on
// this connection. Keeping that selection avoids one redundant IMAP round trip
// for every visible row.
func (c *imapConn) fetchSelectedMessageSummary(folder, id string) (Message, error) {
	if !validIMAPUID(id) {
		return Message{}, errors.New("invalid imap message id")
	}
	lines, err := c.cmd("UID FETCH " + id + " (FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO CC SUBJECT DATE CONTENT-TYPE CONTENT-DISPOSITION)])")
	if err != nil {
		return Message{}, err
	}
	raw := imapLiteralPayload(lines)
	if raw == "" {
		return Message{}, errors.New("imap fetch returned no message summary")
	}
	parsed, err := mail.ReadMessage(bytes.NewReader([]byte(raw)))
	if err != nil {
		return Message{}, errors.New("invalid imap message summary")
	}
	date, _ := mail.ParseDate(parsed.Header.Get("Date"))
	decoder := mime.WordDecoder{}
	decode := func(value string) string {
		decoded, decodeErr := decoder.DecodeHeader(value)
		if decodeErr != nil {
			return value
		}
		return decoded
	}
	message := Message{
		ID: id, Folder: folder, From: decode(parsed.Header.Get("From")), To: decode(parsed.Header.Get("To")), Cc: decode(parsed.Header.Get("Cc")),
		Subject: decode(parsed.Header.Get("Subject")), Date: date,
		HasAttachments: strings.HasPrefix(strings.ToLower(parsed.Header.Get("Content-Type")), "multipart/mixed") || strings.Contains(strings.ToLower(parsed.Header.Get("Content-Disposition")), "attachment"),
	}
	message.Flags = imapMessageFlags(lines)
	return message, nil
}

func imapLiteralPayload(lines []string) string {
	for _, line := range lines {
		if strings.Contains(line, "\r\n") || strings.Contains(line, "Subject:") || strings.Contains(line, "From:") {
			return line
		}
	}
	return ""
}

func imapMessageFlags(lines []string) []string {
	for _, line := range lines {
		match := imapFlags.FindStringSubmatch(line)
		if len(match) == 2 {
			return strings.Fields(match[1])
		}
	}
	return nil
}

var imapFlags = regexp.MustCompile(`(?i)FLAGS[[:space:]]+\(([^)]*)\)`)

func validIMAPUID(id string) bool {
	n, err := strconv.ParseUint(id, 10, 63)
	return err == nil && n > 0
}

func hasFolder(folders []string, want string) bool {
	for _, folder := range folders {
		if strings.EqualFold(folder, want) {
			return true
		}
	}
	return false
}

func folderNames(lines []string) ([]string, error) {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasPrefix(line, "* LIST ") {
			continue
		}
		name := imapMailboxName(line)
		if name == "" || name == "." {
			continue
		}
		if len(out) >= 256 {
			return nil, errors.New("imap folder limit exceeded")
		}
		out = append(out, name)
	}
	return out, nil
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

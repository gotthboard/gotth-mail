package webmail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"
)

const (
	maxMIMEBodyBytes   = int64(1 << 20)
	maxMIMEPartBytes   = int64(25 << 20)
	maxMIMEParts       = 100
	maxMIMENesting     = 8
	maxMIMEHeaderBytes = int64(256 << 10)
)

// ParseRawMessage parses a raw RFC 5322 message into the conservative webmail
// message shape. It is intentionally bounded: malformed MIME, recursion bombs,
// and attachment floods fail closed instead of becoming UI input.
func ParseRawMessage(id, folder string, raw []byte) (Message, error) {
	if int64(len(raw)) > maxMIMEHeaderBytes+maxMIMEBodyBytes+(maxMIMEPartBytes*4) {
		return Message{}, errors.New("message too large")
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return Message{}, err
	}
	date, _ := mail.ParseDate(msg.Header.Get("Date"))
	out := Message{ID: id, Folder: folder, From: msg.Header.Get("From"), To: msg.Header.Get("To"), Cc: msg.Header.Get("Cc"), Subject: msg.Header.Get("Subject"), Date: date}
	if out.Date.IsZero() {
		out.Date = time.Time{}
	}
	parts := 0
	if err := parseMIMEEntity(msg.Header, msg.Body, &out, 0, &parts); err != nil {
		return Message{}, err
	}
	return out, nil
}

func parseMIMEEntity(header mail.Header, r io.Reader, out *Message, depth int, parts *int) error {
	if depth > maxMIMENesting {
		return errors.New("mime nesting limit exceeded")
	}
	(*parts)++
	if *parts > maxMIMEParts {
		return errors.New("mime part limit exceeded")
	}
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	mediaType = strings.ToLower(mediaType)
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" || strings.ContainsAny(boundary, "\r\n") {
			return errors.New("invalid multipart boundary")
		}
		mr := multipart.NewReader(r, boundary)
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			mh := mail.Header(part.Header)
			if err := parseMIMEEntity(mh, part, out, depth+1, parts); err != nil {
				return err
			}
		}
		return nil
	}
	body, err := readMIMEPart(header, r)
	if err != nil {
		return err
	}
	disp, dispParams, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
	filename := dispParams["filename"]
	if filename == "" {
		_, ctParams, _ := mime.ParseMediaType(header.Get("Content-Type"))
		filename = ctParams["name"]
	}
	if strings.EqualFold(disp, "attachment") || filename != "" {
		out.Attachments = append(out.Attachments, SafeAttachment(Attachment{Filename: filename, ContentType: mediaType, Size: int64(len(body)), Content: body}))
		out.HasAttachments = true
		return nil
	}
	switch mediaType {
	case "text/plain":
		if out.BodyText == "" {
			out.BodyText = string(body)
		}
	case "text/html":
		if out.BodyHTML == "" {
			out.BodyHTML = string(body)
		}
	default:
		out.Attachments = append(out.Attachments, SafeAttachment(Attachment{Filename: filename, ContentType: mediaType, Size: int64(len(body)), Content: body}))
		out.HasAttachments = true
	}
	return nil
}

func readMIMEPart(header mail.Header, r io.Reader) ([]byte, error) {
	var reader io.Reader = io.LimitReader(r, maxMIMEPartBytes+1)
	switch strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding"))) {
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, reader)
	case "quoted-printable":
		reader = quotedprintable.NewReader(reader)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxMIMEPartBytes {
		return nil, errors.New("mime part too large")
	}
	return body, nil
}

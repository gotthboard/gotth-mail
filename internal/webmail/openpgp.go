package webmail

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	openPGPMICALG                    = "pgp-sha256"
	openPGPMIMEHash                  = crypto.SHA256
	maxOpenPGPDetachedSignatureBytes = 1 << 20
)

var ErrOpenPGPMIMEUnsupportedHash = errors.New("openpgp/mime signing key does not support the required hash")

type OpenPGPMIMESigner struct {
	Entity *protonpgp.Entity
	Now    func() time.Time
}

func (s OpenPGPMIMESigner) SignMIME(ctx context.Context, identity Identity, msg []byte) ([]byte, SignatureStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, SignatureStatus{}, err
	}
	if s.Entity == nil || s.Entity.PrivateKey == nil || s.Entity.PrimaryKey == nil {
		return nil, SignatureStatus{}, errors.New("openpgp private entity required")
	}
	if len(msg) == 0 {
		return nil, SignatureStatus{}, errors.New("mime message required")
	}
	fingerprint := strings.ToUpper(fmt.Sprintf("%X", s.Entity.PrimaryKey.Fingerprint))
	if identity.Address == "" || identity.Fingerprint == "" || !strings.EqualFold(identity.Fingerprint, fingerprint) {
		return nil, SignatureStatus{Fingerprint: fingerprint, Identity: identity.Address}, errors.New("openpgp identity fingerprint mismatch")
	}
	from, err := messageAddress(msg, "From")
	if err != nil {
		return nil, SignatureStatus{Fingerprint: fingerprint, Identity: identity.Address}, err
	}
	if !strings.EqualFold(from, identity.Address) {
		return nil, SignatureStatus{Fingerprint: fingerprint, Identity: identity.Address}, errors.New("openpgp sender identity mismatch")
	}
	orig, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		return nil, SignatureStatus{Fingerprint: fingerprint, Identity: identity.Address}, err
	}
	binding, err := authoritativeMessageBinding(orig.Header)
	if err != nil {
		return nil, SignatureStatus{Fingerprint: fingerprint, Identity: identity.Address}, err
	}
	body, err := io.ReadAll(orig.Body)
	if err != nil {
		return nil, SignatureStatus{Fingerprint: fingerprint, Identity: identity.Address}, err
	}
	ct := orig.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=utf-8"
	}
	var entity bytes.Buffer
	entity.WriteString("Content-Type: " + ct + "\r\n")
	entity.WriteString("X-GopherMailForge-Signed-From: " + identity.Address + "\r\n")
	entity.WriteString("X-GopherMailForge-Signing-Fingerprint: " + fingerprint + "\r\n")
	entity.WriteString("X-GopherMailForge-Signed-Message-ID: " + binding.MessageID + "\r\n")
	entity.WriteString("X-GopherMailForge-Signed-Date: " + binding.Date.UTC().Format(time.RFC3339Nano) + "\r\n")
	entity.WriteString("X-GopherMailForge-Signed-Subject-SHA256: " + binding.SubjectSHA256 + "\r\n")
	if binding.Sender != "" {
		entity.WriteString("X-GopherMailForge-Signed-Sender: " + binding.Sender + "\r\n")
	}
	if binding.ReplyTo != "" {
		entity.WriteString("X-GopherMailForge-Signed-Reply-To: " + binding.ReplyTo + "\r\n")
	}
	entity.WriteString("\r\n")
	entity.Write(body)
	if !bytes.HasSuffix(entity.Bytes(), []byte("\r\n")) {
		entity.WriteString("\r\n")
	}
	signedData := entity.Bytes()
	sig, err := armoredDetachSignOpenPGPMIME(s.Entity, signedData, s.now)
	if err != nil {
		return nil, SignatureStatus{Fingerprint: fingerprint, Identity: identity.Address}, err
	}
	boundary := "gmf-openpgp-" + safeToken(18)
	var out bytes.Buffer
	for _, h := range []string{"From", "Sender", "Reply-To", "To", "Date", "Message-ID", "Subject"} {
		if v := orig.Header.Get(h); v != "" {
			out.WriteString(h + ": " + v + "\r\n")
		}
	}
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=" + openPGPMICALG + "; boundary=\"" + boundary + "\"\r\n\r\n")
	out.WriteString("--" + boundary + "\r\n")
	out.Write(signedData)
	// RFC 3156 section 5 makes the CRLF immediately before a MIME boundary
	// part of the delimiter, not the signed entity. Keep it separate from the
	// canonical terminal CRLF already present in signedData.
	out.WriteString("\r\n--" + boundary + "\r\n")
	out.WriteString("Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n")
	out.WriteString("Content-Description: OpenPGP digital signature\r\n")
	out.WriteString("Content-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n")
	out.Write(sig)
	if !bytes.HasSuffix(sig, []byte("\r\n")) {
		out.WriteString("\r\n")
	}
	out.WriteString("\r\n--" + boundary + "--\r\n")
	return out.Bytes(), SignatureStatus{Fingerprint: fingerprint, Identity: identity.Address, Signed: true}, nil
}

func (s OpenPGPMIMESigner) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

type OpenPGPMIMEVerifier struct {
	KeyRing protonpgp.KeyRing
	Now     func() time.Time
}

func (v OpenPGPMIMEVerifier) VerifyExactSender(ctx context.Context, signed []byte, expected Identity) (SignatureStatus, error) {
	if err := ctx.Err(); err != nil {
		return SignatureStatus{}, err
	}
	if v.KeyRing == nil {
		return SignatureStatus{}, errors.New("openpgp public keyring required")
	}
	signedPart, sigPart, err := splitOpenPGPMIME(signed)
	if err != nil {
		return SignatureStatus{}, err
	}
	signature, err := decodeArmoredDetachedSignature(sigPart, openPGPMIMEHash)
	if err != nil {
		return SignatureStatus{}, err
	}
	cfg := &packet.Config{DefaultHash: openPGPMIMEHash, Time: v.now}
	entity, err := protonpgp.CheckDetachedSignatureAndHash(v.KeyRing, bytes.NewReader(signedPart), bytes.NewReader(signature), []crypto.Hash{openPGPMIMEHash}, cfg)
	if err != nil {
		return SignatureStatus{}, err
	}
	fingerprint := strings.ToUpper(fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint))
	from, err := messageAddress(signed, "From")
	if err != nil {
		return SignatureStatus{Fingerprint: fingerprint}, err
	}
	binding, err := authoritativeMessageBindingFromBytes(signed)
	if err != nil {
		return SignatureStatus{Fingerprint: fingerprint, Identity: from}, err
	}
	asserted, err := signedEntityAssertions(signedPart)
	if err != nil {
		return SignatureStatus{Fingerprint: fingerprint, Identity: from}, err
	}
	status := SignatureStatus{Fingerprint: fingerprint, Identity: from, Signed: true}
	if expected.Address == "" || expected.Fingerprint == "" ||
		!strings.EqualFold(expected.Address, from) ||
		!strings.EqualFold(expected.Address, asserted.From) ||
		!strings.EqualFold(expected.Fingerprint, fingerprint) ||
		!strings.EqualFold(expected.Fingerprint, asserted.Fingerprint) ||
		binding.MessageID != asserted.MessageID ||
		!binding.Date.Equal(asserted.Date) ||
		binding.SubjectSHA256 != asserted.SubjectSHA256 ||
		!strings.EqualFold(binding.Sender, asserted.Sender) ||
		!strings.EqualFold(binding.ReplyTo, asserted.ReplyTo) {
		return status, errors.New("openpgp exact sender verification failed")
	}
	return status, nil
}

// ValidateOpenPGPMIMESHA256SigningKey rejects keys for which go-crypto's
// detached-signature path deterministically selects a stronger, incompatible
// hash even when SHA-256 is configured. The signer still inspects the emitted
// packet, so a future library selection change fails closed.
func ValidateOpenPGPMIMESHA256SigningKey(key *packet.PublicKey) error {
	if key == nil {
		return errors.New("openpgp signing key required")
	}
	unsupported := key.PubKeyAlgo == packet.PubKeyAlgoEd448
	if key.PubKeyAlgo == packet.PubKeyAlgoECDSA || key.PubKeyAlgo == packet.PubKeyAlgoEdDSA {
		curve, err := key.Curve()
		if err != nil {
			return fmt.Errorf("inspect OpenPGP signing key curve: %w", err)
		}
		switch curve {
		case packet.Curve448, packet.CurveNistP384, packet.CurveNistP521,
			packet.CurveBrainpoolP384, packet.CurveBrainpoolP512:
			unsupported = true
		}
	}
	if unsupported {
		return fmt.Errorf("%w: public-key algorithm %v", ErrOpenPGPMIMEUnsupportedHash, key.PubKeyAlgo)
	}
	return nil
}

func armoredDetachSignOpenPGPMIME(entity *protonpgp.Entity, signedData []byte, now func() time.Time) ([]byte, error) {
	var sig bytes.Buffer
	cfg := &packet.Config{DefaultHash: openPGPMIMEHash, Time: now}
	if err := protonpgp.ArmoredDetachSign(&sig, entity, bytes.NewReader(signedData), cfg); err != nil {
		return nil, err
	}
	if err := requireArmoredDetachedSignatureHash(sig.Bytes(), openPGPMIMEHash); err != nil {
		return nil, err
	}
	return sig.Bytes(), nil
}

func decodeArmoredDetachedSignature(signature []byte, expected crypto.Hash) ([]byte, error) {
	normalized, err := canonicalArmorBytes(signature)
	if err != nil {
		return nil, err
	}
	block, err := armor.Decode(bytes.NewReader(normalized))
	if err != nil {
		return nil, fmt.Errorf("decode OpenPGP detached signature: %w", err)
	}
	if block.Type != protonpgp.SignatureType {
		return nil, errors.New("invalid OpenPGP detached signature armor type")
	}
	if len(block.Header) != 0 {
		return nil, errors.New("OpenPGP detached signature armor contains headers")
	}
	packetBytes, err := io.ReadAll(io.LimitReader(block.Body, maxOpenPGPDetachedSignatureBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read OpenPGP detached signature armor: %w", err)
	}
	if len(packetBytes) == 0 || len(packetBytes) > maxOpenPGPDetachedSignatureBytes {
		return nil, errors.New("invalid OpenPGP detached signature size")
	}
	var canonical bytes.Buffer
	armored, err := armor.Encode(&canonical, protonpgp.SignatureType, nil)
	if err != nil {
		return nil, fmt.Errorf("encode canonical OpenPGP detached signature: %w", err)
	}
	if _, err := armored.Write(packetBytes); err != nil {
		return nil, fmt.Errorf("encode canonical OpenPGP detached signature: %w", err)
	}
	if err := armored.Close(); err != nil {
		return nil, fmt.Errorf("encode canonical OpenPGP detached signature: %w", err)
	}
	if !bytes.Equal(normalized, bytes.TrimSpace(canonical.Bytes())) {
		return nil, errors.New("OpenPGP detached signature is not one canonical armor block")
	}
	if err := requireDetachedSignaturePacketHash(packetBytes, expected); err != nil {
		return nil, err
	}
	return packetBytes, nil
}

func requireArmoredDetachedSignatureHash(signature []byte, expected crypto.Hash) error {
	_, err := decodeArmoredDetachedSignature(signature, expected)
	return err
}

func requireDetachedSignaturePacketHash(packetBytes []byte, expected crypto.Hash) error {
	body := bytes.NewReader(packetBytes)
	p, err := packet.Read(body)
	if err != nil {
		return fmt.Errorf("read OpenPGP detached signature packet: %w", err)
	}
	sig, ok := p.(*packet.Signature)
	if !ok {
		return errors.New("OpenPGP detached signature armor does not contain a signature packet")
	}
	if sig.Hash != expected {
		return fmt.Errorf("%w: OpenPGP detached signature uses %s, want %s hash algorithm", ErrOpenPGPMIMEUnsupportedHash, sig.Hash, expected)
	}
	if _, err := packet.Read(body); err == nil {
		return errors.New("OpenPGP detached signature armor contains multiple packets")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("read trailing OpenPGP detached signature packet: %w", err)
	}
	return nil
}

func canonicalArmorBytes(signature []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(signature)
	if len(trimmed) == 0 {
		return nil, errors.New("OpenPGP detached signature armor required")
	}
	normalized := make([]byte, 0, len(trimmed))
	for i := 0; i < len(trimmed); i++ {
		switch trimmed[i] {
		case '\r':
			if i+1 >= len(trimmed) || trimmed[i+1] != '\n' {
				return nil, errors.New("OpenPGP detached signature armor uses non-canonical line endings")
			}
			normalized = append(normalized, '\n')
			i++
		default:
			normalized = append(normalized, trimmed[i])
		}
	}
	return normalized, nil
}

func (v OpenPGPMIMEVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now().UTC()
	}
	return time.Now().UTC()
}

func splitOpenPGPMIME(b []byte) ([]byte, []byte, error) {
	msg, body, err := readCanonicalMIMEEntity(b)
	if err != nil {
		return nil, nil, err
	}
	if err := rejectAmbiguousHeaders(msg.Header,
		"From", "Sender", "Reply-To", "Message-ID", "Date", "Subject", "MIME-Version",
	); err != nil {
		return nil, nil, err
	}
	ct, err := uniqueHeaderValue(msg.Header, "Content-Type", true)
	if err != nil {
		return nil, nil, err
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.EqualFold(mt, "multipart/signed") || !strings.EqualFold(params["protocol"], "application/pgp-signature") || !strings.EqualFold(params["micalg"], openPGPMICALG) || params["boundary"] == "" {
		return nil, nil, errors.New("invalid OpenPGP/MIME signed wrapper")
	}
	limit := maxMIMEHeaderBytes + maxMIMEBodyBytes + (maxMIMEPartBytes * 4)
	parts, err := splitRawMIMEParts(body, params["boundary"])
	if err != nil || len(parts) != 2 {
		return nil, nil, errors.New("invalid OpenPGP/MIME part count")
	}
	if int64(len(parts[0])) > limit {
		return nil, nil, errors.New("OpenPGP/MIME signed data too large")
	}
	if _, _, err := readCanonicalMIMEEntity(parts[0]); err != nil {
		return nil, nil, errors.New("invalid OpenPGP/MIME signed data part")
	}
	second, sigBody, err := readCanonicalMIMEEntity(parts[1])
	if err != nil {
		return nil, nil, errors.New("invalid OpenPGP/MIME signature part")
	}
	if err := rejectAmbiguousSecurityHeaders(second.Header); err != nil {
		return nil, nil, err
	}
	sigContentType, err := uniqueHeaderValue(second.Header, "Content-Type", true)
	if err != nil {
		return nil, nil, err
	}
	sigType, _, err := mime.ParseMediaType(sigContentType)
	if err != nil || !strings.EqualFold(sigType, "application/pgp-signature") {
		return nil, nil, errors.New("invalid OpenPGP/MIME signature content type")
	}
	sig, err := io.ReadAll(io.LimitReader(bytes.NewReader(sigBody), (1<<20)+1))
	if err != nil {
		return nil, nil, err
	}
	if len(sig) == 0 || len(sig) > 1<<20 || !bytes.Contains(sig, []byte("BEGIN PGP SIGNATURE")) {
		return nil, nil, errors.New("invalid OpenPGP signature part")
	}
	return parts[0], sig, nil
}

// splitRawMIMEParts returns each MIME entity exactly as transmitted. The CRLF
// immediately before a boundary belongs to the delimiter and is therefore not
// returned as part data. Reconstructing parsed MIME headers here would silently
// remove, reorder, or normalize bytes that the detached signature must cover.
func splitRawMIMEParts(body []byte, boundary string) ([][]byte, error) {
	if boundary == "" {
		return nil, errors.New("empty MIME boundary")
	}
	marker := []byte("--" + boundary)
	var parts [][]byte
	searchFrom := 0
	partStart := -1
	for {
		start, after, final, ok := nextRawBoundary(body, marker, searchFrom)
		if !ok {
			return nil, errors.New("unterminated MIME multipart")
		}
		if partStart < 0 {
			if final {
				return nil, errors.New("MIME multipart has no parts")
			}
			partStart = after
			searchFrom = after
			continue
		}
		partEnd := start - 2 // The delimiter owns its immediately preceding CRLF.
		if partEnd < partStart || !bytes.Equal(body[partEnd:start], []byte("\r\n")) {
			return nil, errors.New("invalid MIME boundary separation")
		}
		parts = append(parts, body[partStart:partEnd])
		if final {
			return parts, nil
		}
		partStart = after
		searchFrom = after
	}
}

func nextRawBoundary(body, marker []byte, from int) (start, after int, final, ok bool) {
	for from <= len(body) {
		rel := bytes.Index(body[from:], marker)
		if rel < 0 {
			return 0, 0, false, false
		}
		start = from + rel
		if start != 0 && (start < 2 || !bytes.Equal(body[start-2:start], []byte("\r\n"))) {
			from = start + 1
			continue
		}
		pos := start + len(marker)
		if pos+2 <= len(body) && bytes.Equal(body[pos:pos+2], []byte("--")) {
			final = true
			pos += 2
		}
		for pos < len(body) && (body[pos] == ' ' || body[pos] == '\t') {
			pos++
		}
		if pos == len(body) {
			if final {
				return start, pos, true, true
			}
			return 0, 0, false, false
		}
		if pos+2 <= len(body) && bytes.Equal(body[pos:pos+2], []byte("\r\n")) {
			return start, pos + 2, final, true
		}
		from = start + 1
	}
	return 0, 0, false, false
}

func readCanonicalMIMEEntity(raw []byte) (*mail.Message, []byte, error) {
	separator := bytes.Index(raw, []byte("\r\n\r\n"))
	if separator < 0 {
		return nil, nil, errors.New("MIME entity lacks canonical header separator")
	}
	for i := 0; i < separator+2; i++ {
		switch raw[i] {
		case '\r':
			if i+1 >= len(raw) || raw[i+1] != '\n' {
				return nil, nil, errors.New("MIME headers use non-canonical line endings")
			}
		case '\n':
			if i == 0 || raw[i-1] != '\r' {
				return nil, nil, errors.New("MIME headers use non-canonical line endings")
			}
		}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	return msg, raw[separator+4:], nil
}

func validateSignedEntityHeaders(h mail.Header) error {
	if err := rejectAmbiguousSecurityHeaders(h); err != nil {
		return err
	}
	for _, field := range []string{
		"Content-Type",
		"X-GopherMailForge-Signed-From",
		"X-GopherMailForge-Signing-Fingerprint",
		"X-GopherMailForge-Signed-Message-ID",
		"X-GopherMailForge-Signed-Date",
		"X-GopherMailForge-Signed-Subject-SHA256",
	} {
		if _, err := uniqueHeaderValue(h, field, true); err != nil {
			return err
		}
	}
	return rejectAmbiguousHeaders(h,
		"X-GopherMailForge-Signed-Sender",
		"X-GopherMailForge-Signed-Reply-To",
	)
}

func rejectAmbiguousSecurityHeaders(h mail.Header) error {
	for field, values := range h {
		lower := strings.ToLower(field)
		if (strings.HasPrefix(lower, "content-") || strings.HasPrefix(lower, "x-gophermailforge-")) && len(values) != 1 {
			return errors.New("ambiguous " + lower + " header")
		}
	}
	return nil
}

func rejectAmbiguousHeaders(h mail.Header, fields ...string) error {
	for _, field := range fields {
		if _, err := uniqueHeaderValue(h, field, false); err != nil {
			return err
		}
	}
	return rejectAmbiguousSecurityHeaders(h)
}

func uniqueHeaderValue(h mail.Header, field string, required bool) (string, error) {
	values := h[textproto.CanonicalMIMEHeaderKey(field)]
	if len(values) == 0 {
		if required {
			return "", errors.New("missing " + strings.ToLower(field) + " header")
		}
		return "", nil
	}
	if len(values) != 1 {
		return "", errors.New("ambiguous " + strings.ToLower(field) + " header")
	}
	return values[0], nil
}

type authoritativeBinding struct {
	From, Sender, ReplyTo, MessageID, SubjectSHA256, Fingerprint string
	Date                                                         time.Time
}

func signedEntityAssertions(entity []byte) (authoritativeBinding, error) {
	m, _, err := readCanonicalMIMEEntity(entity)
	if err != nil {
		return authoritativeBinding{}, err
	}
	if err := validateSignedEntityHeaders(m.Header); err != nil {
		return authoritativeBinding{}, err
	}
	from, err := uniqueHeaderValue(m.Header, "X-GopherMailForge-Signed-From", true)
	if err != nil {
		return authoritativeBinding{}, err
	}
	fingerprint, err := uniqueHeaderValue(m.Header, "X-GopherMailForge-Signing-Fingerprint", true)
	if err != nil {
		return authoritativeBinding{}, err
	}
	messageID, err := uniqueHeaderValue(m.Header, "X-GopherMailForge-Signed-Message-ID", true)
	if err != nil {
		return authoritativeBinding{}, err
	}
	dateValue, err := uniqueHeaderValue(m.Header, "X-GopherMailForge-Signed-Date", true)
	if err != nil {
		return authoritativeBinding{}, err
	}
	subjectSHA256, err := uniqueHeaderValue(m.Header, "X-GopherMailForge-Signed-Subject-SHA256", true)
	if err != nil {
		return authoritativeBinding{}, err
	}
	sender, err := uniqueHeaderValue(m.Header, "X-GopherMailForge-Signed-Sender", false)
	if err != nil {
		return authoritativeBinding{}, err
	}
	replyTo, err := uniqueHeaderValue(m.Header, "X-GopherMailForge-Signed-Reply-To", false)
	if err != nil {
		return authoritativeBinding{}, err
	}
	out := authoritativeBinding{
		From:          strings.ToLower(strings.TrimSpace(from)),
		Fingerprint:   strings.ToUpper(strings.TrimSpace(fingerprint)),
		MessageID:     strings.TrimSpace(messageID),
		SubjectSHA256: strings.ToLower(strings.TrimSpace(subjectSHA256)),
		Sender:        strings.ToLower(strings.TrimSpace(sender)),
		ReplyTo:       strings.ToLower(strings.TrimSpace(replyTo)),
	}
	out.Date, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(dateValue))
	if err != nil || out.From == "" || out.Fingerprint == "" || out.MessageID == "" || out.SubjectSHA256 == "" {
		return authoritativeBinding{}, errors.New("missing OpenPGP sender binding assertion")
	}
	return out, nil
}

func authoritativeMessageBindingFromBytes(msg []byte) (authoritativeBinding, error) {
	m, _, err := readCanonicalMIMEEntity(msg)
	if err != nil {
		return authoritativeBinding{}, err
	}
	return authoritativeMessageBinding(m.Header)
}

func authoritativeMessageBinding(h mail.Header) (authoritativeBinding, error) {
	from, err := headerAddress(h, "From", true)
	if err != nil {
		return authoritativeBinding{}, err
	}
	sender, err := headerAddress(h, "Sender", false)
	if err != nil {
		return authoritativeBinding{}, err
	}
	replyTo, err := headerAddress(h, "Reply-To", false)
	if err != nil {
		return authoritativeBinding{}, err
	}
	messageIDHeader, err := uniqueHeaderValue(h, "Message-ID", true)
	if err != nil {
		return authoritativeBinding{}, err
	}
	messageID := strings.TrimSpace(messageIDHeader)
	if _, err := messageIDValue(messageID); err != nil {
		return authoritativeBinding{}, err
	}
	dateHeader, err := uniqueHeaderValue(h, "Date", true)
	if err != nil {
		return authoritativeBinding{}, err
	}
	date, err := mail.ParseDate(dateHeader)
	if err != nil {
		return authoritativeBinding{}, errors.New("invalid date header")
	}
	subject, err := uniqueHeaderValue(h, "Subject", true)
	if err != nil {
		return authoritativeBinding{}, err
	}
	if strings.ContainsAny(subject, "\r\n") {
		return authoritativeBinding{}, errors.New("invalid subject header")
	}
	digest := sha256.Sum256([]byte(subject))
	return authoritativeBinding{From: from, Sender: sender, ReplyTo: replyTo, MessageID: messageID, Date: date.UTC(), SubjectSHA256: fmt.Sprintf("%x", digest)}, nil
}

func messageIDValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	if strings.ContainsAny(v, "\r\n") || len(v) > 255 || !strings.HasPrefix(v, "<") || !strings.HasSuffix(v, ">") {
		return "", errors.New("invalid message id")
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(v, "<"), ">")
	if strings.Count(inner, "@") != 1 || strings.ContainsAny(inner, " <>\t") {
		return "", errors.New("invalid message id")
	}
	return v, nil
}

func headerAddress(h mail.Header, field string, required bool) (string, error) {
	header, err := uniqueHeaderValue(h, field, required)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(header)
	if v == "" && !required {
		return "", nil
	}
	addresses, err := mail.ParseAddressList(v)
	if err != nil || len(addresses) != 1 || addresses[0].Address == "" {
		return "", errors.New("invalid " + strings.ToLower(field) + " address")
	}
	return strings.ToLower(addresses[0].Address), nil
}

func messageAddress(msg []byte, field string) (string, error) {
	m, _, err := readCanonicalMIMEEntity(msg)
	if err != nil {
		return "", err
	}
	return headerAddress(m.Header, field, true)
}

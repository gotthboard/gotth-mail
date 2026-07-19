package webmail

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"time"

	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

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
	entity.WriteString("X-GopherMailForge-Signing-Fingerprint: " + fingerprint + "\r\n\r\n")
	entity.Write(body)
	if !bytes.HasSuffix(entity.Bytes(), []byte("\r\n")) {
		entity.WriteString("\r\n")
	}
	signedData := entity.Bytes()
	var sig bytes.Buffer
	cfg := &packet.Config{DefaultHash: crypto.SHA256, Time: s.now}
	if err := protonpgp.ArmoredDetachSign(&sig, s.Entity, bytes.NewReader(signedData), cfg); err != nil {
		return nil, SignatureStatus{Fingerprint: fingerprint, Identity: identity.Address}, err
	}
	boundary := "gmf-openpgp-" + safeToken(18)
	var out bytes.Buffer
	for _, h := range []string{"From", "To", "Date", "Subject"} {
		if v := orig.Header.Get(h); v != "" {
			out.WriteString(h + ": " + v + "\r\n")
		}
	}
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"" + boundary + "\"\r\n\r\n")
	out.WriteString("--" + boundary + "\r\n")
	out.Write(signedData)
	out.WriteString("--" + boundary + "\r\n")
	out.WriteString("Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n")
	out.WriteString("Content-Description: OpenPGP digital signature\r\n")
	out.WriteString("Content-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n")
	out.Write(sig.Bytes())
	if !bytes.HasSuffix(sig.Bytes(), []byte("\r\n")) {
		out.WriteString("\r\n")
	}
	out.WriteString("--" + boundary + "--\r\n")
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
	cfg := &packet.Config{DefaultHash: crypto.SHA256, Time: v.now}
	entity, err := protonpgp.CheckArmoredDetachedSignature(v.KeyRing, bytes.NewReader(signedPart), bytes.NewReader(sigPart), cfg)
	if err != nil {
		return SignatureStatus{}, err
	}
	fingerprint := strings.ToUpper(fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint))
	from, err := messageAddress(signed, "From")
	if err != nil {
		return SignatureStatus{Fingerprint: fingerprint}, err
	}
	assertedFrom, assertedFingerprint, err := signedEntityAssertions(signedPart)
	if err != nil {
		return SignatureStatus{Fingerprint: fingerprint, Identity: from}, err
	}
	status := SignatureStatus{Fingerprint: fingerprint, Identity: from, Signed: true}
	if expected.Address == "" || expected.Fingerprint == "" || !strings.EqualFold(expected.Address, from) || !strings.EqualFold(expected.Address, assertedFrom) || !strings.EqualFold(expected.Fingerprint, fingerprint) || !strings.EqualFold(expected.Fingerprint, assertedFingerprint) {
		return status, errors.New("openpgp exact sender verification failed")
	}
	return status, nil
}

func (v OpenPGPMIMEVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now().UTC()
	}
	return time.Now().UTC()
}

func splitOpenPGPMIME(b []byte) ([]byte, []byte, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	ct := msg.Header.Get("Content-Type")
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.EqualFold(mt, "multipart/signed") || !strings.EqualFold(params["protocol"], "application/pgp-signature") || !strings.EqualFold(params["micalg"], "pgp-sha256") || params["boundary"] == "" {
		return nil, nil, errors.New("invalid OpenPGP/MIME signed wrapper")
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	first, err := mr.NextPart()
	if err != nil {
		return nil, nil, errors.New("missing OpenPGP/MIME signed data part")
	}
	limit := maxMIMEHeaderBytes + maxMIMEBodyBytes + (maxMIMEPartBytes * 4)
	body, err := io.ReadAll(io.LimitReader(first, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(body)) > limit {
		return nil, nil, errors.New("OpenPGP/MIME signed data too large")
	}
	var entity bytes.Buffer
	for _, h := range []string{"Content-Type", "X-GopherMailForge-Signed-From", "X-GopherMailForge-Signing-Fingerprint"} {
		if v := first.Header.Get(h); v != "" {
			entity.WriteString(h + ": " + v + "\r\n")
		}
	}
	entity.WriteString("\r\n")
	entity.Write(body)
	if !bytes.HasSuffix(entity.Bytes(), []byte("\r\n")) {
		entity.WriteString("\r\n")
	}
	signedPart := entity.Bytes()
	second, err := mr.NextPart()
	if err != nil {
		return nil, nil, errors.New("missing OpenPGP/MIME signature part")
	}
	sigType, _, err := mime.ParseMediaType(second.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(sigType, "application/pgp-signature") {
		return nil, nil, errors.New("invalid OpenPGP/MIME signature content type")
	}
	sig, err := io.ReadAll(io.LimitReader(second, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	if len(sig) == 0 || !bytes.Contains(sig, []byte("BEGIN PGP SIGNATURE")) {
		return nil, nil, errors.New("invalid OpenPGP signature part")
	}
	if _, err := mr.NextPart(); err != io.EOF {
		return nil, nil, errors.New("unexpected OpenPGP/MIME extra part")
	}
	return signedPart, sig, nil
}

func signedEntityAssertions(entity []byte) (string, string, error) {
	m, err := mail.ReadMessage(bytes.NewReader(entity))
	if err != nil {
		return "", "", err
	}
	from := strings.ToLower(strings.TrimSpace(m.Header.Get("X-GopherMailForge-Signed-From")))
	fingerprint := strings.ToUpper(strings.TrimSpace(m.Header.Get("X-GopherMailForge-Signing-Fingerprint")))
	if from == "" || fingerprint == "" {
		return "", "", errors.New("missing OpenPGP sender binding assertion")
	}
	return from, fingerprint, nil
}

func messageAddress(msg []byte, field string) (string, error) {
	m, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		return "", err
	}
	a, err := mail.ParseAddress(m.Header.Get(field))
	if err != nil || a.Address == "" {
		return "", errors.New("invalid " + strings.ToLower(field) + " address")
	}
	return strings.ToLower(a.Address), nil
}

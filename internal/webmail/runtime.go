package webmail

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
)

const (
	maxWebmailRuntimeConfigBytes = 1 << 20
	maxWebmailSecretBytes        = 4 << 10
	maxWebmailPrivateKeyBytes    = 8 << 20
)

// RuntimeConfig is the complete production transport/signing boundary for
// custom webmail. Passwords stay in distinct protected files and are reloaded
// for each connection so rotation does not require putting secrets in JSON or
// restarting the control plane.
type RuntimeConfig struct {
	IMAPAddr      string           `json:"imap_addr"`
	SMTPAddr      string           `json:"smtp_addr"`
	SMTPHelloName string           `json:"smtp_hello_name"`
	Mailboxes     []RuntimeMailbox `json:"mailboxes"`
}

type RuntimeMailbox struct {
	Address            string `json:"address"`
	IMAPPasswordFile   string `json:"imap_password_file"`
	SMTPPasswordFile   string `json:"smtp_password_file"`
	SigningFingerprint string `json:"signing_fingerprint"`
	PrivateKeyFile     string `json:"private_key_file"`
}

// RuntimeRegistry selects credentials and signing material only by the exact
// authenticated mailbox address. It implements the IMAP, SMTP, resolver,
// signer, and verifier seams used by Client and Sender.
type RuntimeRegistry struct {
	imapAddr, smtpAddr, smtpHelloName string
	mailboxes                         map[string]RuntimeMailbox
	now                               func() time.Time
}

func NewRuntimeRegistryFromFile(path string) (*RuntimeRegistry, error) {
	raw, err := readProtectedFile(path, maxWebmailRuntimeConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("read webmail runtime config: %w", err)
	}
	var cfg RuntimeConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode webmail runtime config: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return nil, err
	}
	return NewRuntimeRegistry(cfg)
}

func NewRuntimeRegistry(cfg RuntimeConfig) (*RuntimeRegistry, error) {
	if err := validatePrivateServiceAddress(cfg.IMAPAddr); err != nil {
		return nil, fmt.Errorf("webmail imap address: %w", err)
	}
	if err := validatePrivateServiceAddress(cfg.SMTPAddr); err != nil {
		return nil, fmt.Errorf("webmail smtp address: %w", err)
	}
	if strings.ContainsAny(cfg.SMTPHelloName, "\r\n") {
		return nil, errors.New("webmail smtp hello name contains newline")
	}
	if len(cfg.Mailboxes) == 0 {
		return nil, errors.New("webmail runtime requires at least one mailbox")
	}
	r := &RuntimeRegistry{
		imapAddr: strings.TrimSpace(cfg.IMAPAddr), smtpAddr: strings.TrimSpace(cfg.SMTPAddr),
		smtpHelloName: strings.TrimSpace(cfg.SMTPHelloName), mailboxes: make(map[string]RuntimeMailbox, len(cfg.Mailboxes)),
		now: func() time.Time { return time.Now().UTC() },
	}
	if r.smtpHelloName == "" {
		r.smtpHelloName = "gotth-mail-webmail"
	}
	for _, configured := range cfg.Mailboxes {
		address, err := canonicalRuntimeAddress(configured.Address)
		if err != nil {
			return nil, err
		}
		if _, exists := r.mailboxes[address]; exists {
			return nil, fmt.Errorf("duplicate webmail runtime mailbox %q", address)
		}
		configured.Address = address
		configured.SigningFingerprint, err = canonicalRuntimeFingerprint(configured.SigningFingerprint)
		if err != nil {
			return nil, fmt.Errorf("webmail runtime mailbox %q: %w", address, err)
		}
		if _, err := readProtectedSecret(configured.IMAPPasswordFile); err != nil {
			return nil, fmt.Errorf("webmail runtime mailbox %q imap password: %w", address, err)
		}
		if _, err := readProtectedSecret(configured.SMTPPasswordFile); err != nil {
			return nil, fmt.Errorf("webmail runtime mailbox %q smtp password: %w", address, err)
		}
		if _, err := loadRuntimeSigningEntity(configured.PrivateKeyFile, configured.SigningFingerprint, address, r.now()); err != nil {
			return nil, fmt.Errorf("webmail runtime mailbox %q signing key: %w", address, err)
		}
		r.mailboxes[address] = configured
	}
	return r, nil
}

func (r *RuntimeRegistry) ListFolders(ctx context.Context, user string) ([]string, error) {
	c, err := r.imapClient(user)
	if err != nil {
		return nil, err
	}
	return c.ListFolders(ctx, user)
}

func (r *RuntimeRegistry) ListFoldersDetailed(ctx context.Context, user string) ([]FolderInfo, error) {
	c, err := r.imapClient(user)
	if err != nil {
		return nil, err
	}
	return c.ListFoldersDetailed(ctx, user)
}

func (r *RuntimeRegistry) ListMessages(ctx context.Context, user, folder, cursor string, limit int) ([]Message, error) {
	c, err := r.imapClient(user)
	if err != nil {
		return nil, err
	}
	return c.ListMessages(ctx, user, folder, cursor, limit)
}

func (r *RuntimeRegistry) ReadMessage(ctx context.Context, user, folder, id string) (Message, error) {
	c, err := r.imapClient(user)
	if err != nil {
		return Message{}, err
	}
	return c.ReadMessage(ctx, user, folder, id)
}

func (r *RuntimeRegistry) Search(ctx context.Context, user, folder, query, cursor string, limit int) ([]Message, error) {
	c, err := r.imapClient(user)
	if err != nil {
		return nil, err
	}
	return c.Search(ctx, user, folder, query, cursor, limit)
}

func (r *RuntimeRegistry) Quota(ctx context.Context, user string) (int64, int64, error) {
	c, err := r.imapClient(user)
	if err != nil {
		return 0, 0, err
	}
	return c.Quota(ctx, user)
}

func (r *RuntimeRegistry) SetFlag(ctx context.Context, user, folder, id, flag string, enabled bool) error {
	c, err := r.imapClient(user)
	if err != nil {
		return err
	}
	return c.SetFlag(ctx, user, folder, id, flag, enabled)
}

func (r *RuntimeRegistry) Move(ctx context.Context, user, folder, id, destination string) error {
	c, err := r.imapClient(user)
	if err != nil {
		return err
	}
	return c.Move(ctx, user, folder, id, destination)
}

func (r *RuntimeRegistry) Delete(ctx context.Context, user, folder, id string) error {
	c, err := r.imapClient(user)
	if err != nil {
		return err
	}
	return c.Delete(ctx, user, folder, id)
}

func (r *RuntimeRegistry) Submit(ctx context.Context, envelope Envelope, msg []byte) error {
	entry, err := r.mailbox(envelope.From)
	if err != nil {
		return err
	}
	password, err := readProtectedSecret(entry.SMTPPasswordFile)
	if err != nil {
		return fmt.Errorf("load webmail smtp credential: %w", err)
	}
	return (NetSMTPSubmitter{
		Addr: r.smtpAddr, HelloName: r.smtpHelloName,
		Auth: smtp.CRAMMD5Auth(entry.Address, password),
	}).Submit(ctx, envelope, msg)
}

func (r *RuntimeRegistry) ResolveSender(ctx context.Context, fingerprint, from, sender string) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	if strings.TrimSpace(sender) != "" {
		return Identity{}, errors.New("webmail sender override is not permitted")
	}
	entry, err := r.mailbox(from)
	if err != nil {
		return Identity{}, err
	}
	fingerprint, err = canonicalRuntimeFingerprint(fingerprint)
	if err != nil || fingerprint != entry.SigningFingerprint {
		return Identity{}, errors.New("webmail exact sender fingerprint mismatch")
	}
	if _, err := loadRuntimeSigningEntity(entry.PrivateKeyFile, entry.SigningFingerprint, entry.Address, r.now()); err != nil {
		return Identity{}, err
	}
	return Identity{Address: entry.Address, Fingerprint: entry.SigningFingerprint}, nil
}

func (r *RuntimeRegistry) DefaultIdentity(ctx context.Context, mailbox string) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	entry, err := r.mailbox(mailbox)
	if err != nil {
		return Identity{}, err
	}
	if _, err := loadRuntimeSigningEntity(entry.PrivateKeyFile, entry.SigningFingerprint, entry.Address, r.now()); err != nil {
		return Identity{}, err
	}
	return Identity{Address: entry.Address, Fingerprint: entry.SigningFingerprint}, nil
}

func (r *RuntimeRegistry) SignMIME(ctx context.Context, identity Identity, msg []byte) ([]byte, SignatureStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, SignatureStatus{}, err
	}
	entry, err := r.mailbox(identity.Address)
	if err != nil {
		return nil, SignatureStatus{}, err
	}
	if identity.Fingerprint != entry.SigningFingerprint {
		return nil, SignatureStatus{}, errors.New("webmail exact sender fingerprint mismatch")
	}
	entity, err := loadRuntimeSigningEntity(entry.PrivateKeyFile, entry.SigningFingerprint, entry.Address, r.now())
	if err != nil {
		return nil, SignatureStatus{}, err
	}
	return (OpenPGPMIMESigner{Entity: entity, Now: r.now}).SignMIME(ctx, identity, msg)
}

func (r *RuntimeRegistry) VerifyExactSender(ctx context.Context, signed []byte, identity Identity) (SignatureStatus, error) {
	if err := ctx.Err(); err != nil {
		return SignatureStatus{}, err
	}
	entry, err := r.mailbox(identity.Address)
	if err != nil {
		return SignatureStatus{}, err
	}
	if identity.Fingerprint != entry.SigningFingerprint {
		return SignatureStatus{}, errors.New("webmail exact sender fingerprint mismatch")
	}
	entity, err := loadRuntimeSigningEntity(entry.PrivateKeyFile, entry.SigningFingerprint, entry.Address, r.now())
	if err != nil {
		return SignatureStatus{}, err
	}
	return (OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: r.now}).VerifyExactSender(ctx, signed, identity)
}

func (r *RuntimeRegistry) imapClient(user string) (NetIMAPClient, error) {
	entry, err := r.mailbox(user)
	if err != nil {
		return NetIMAPClient{}, err
	}
	password, err := readProtectedSecret(entry.IMAPPasswordFile)
	if err != nil {
		return NetIMAPClient{}, fmt.Errorf("load webmail imap credential: %w", err)
	}
	return NetIMAPClient{Addr: r.imapAddr, Username: entry.Address, Password: password}, nil
}

func (r *RuntimeRegistry) mailbox(raw string) (RuntimeMailbox, error) {
	address, err := canonicalRuntimeAddress(raw)
	if err != nil {
		return RuntimeMailbox{}, err
	}
	entry, ok := r.mailboxes[address]
	if !ok {
		return RuntimeMailbox{}, errors.New("webmail mailbox is not configured")
	}
	return entry, nil
}

func canonicalRuntimeAddress(raw string) (string, error) {
	parsed, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil || parsed.Address == "" || !runtimeASCIIAddress(parsed.Address) {
		return "", errors.New("valid ASCII webmail mailbox address required")
	}
	return strings.ToLower(parsed.Address), nil
}

func runtimeASCIIAddress(address string) bool {
	if len(address) == 0 || len(address) > 254 || strings.Count(address, "@") != 1 {
		return false
	}
	for _, ch := range address {
		if ch < 0x21 || ch > 0x7e || ch == '\\' || ch == '"' {
			return false
		}
	}
	return true
}

func canonicalRuntimeFingerprint(raw string) (string, error) {
	fingerprint := strings.ToUpper(strings.TrimSpace(raw))
	if len(fingerprint) != 40 && len(fingerprint) != 64 {
		return "", errors.New("valid webmail signing fingerprint required")
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return "", errors.New("valid webmail signing fingerprint required")
	}
	return fingerprint, nil
}

func validatePrivateServiceAddress(raw string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(host) == "" {
		return errors.New("valid host:port required")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("valid host:port required")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() {
			return nil
		}
		return errors.New("plaintext mail transport must target a private service")
	}
	if len(host) == 0 || len(host) > 63 || strings.Contains(host, ".") || host[0] == '-' || host[len(host)-1] == '-' {
		return errors.New("plaintext mail transport must target a private service")
	}
	for _, ch := range host {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
			return errors.New("plaintext mail transport must target a private service")
		}
	}
	return nil
}

func readProtectedSecret(path string) (string, error) {
	raw, err := readProtectedFile(path, maxWebmailSecretBytes)
	if err != nil {
		return "", err
	}
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	raw = bytes.TrimSuffix(raw, []byte("\r"))
	if len(raw) == 0 || bytes.ContainsAny(raw, "\r\n") {
		return "", errors.New("secret must be one non-empty line")
	}
	return string(raw), nil
}

func readProtectedFile(path string, limit int64) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("protected file path required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("protected file unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("protected file metadata unavailable")
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("protected file must be non-empty, bounded, regular, and owner-only")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("protected file read failed")
	}
	return raw, nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("webmail runtime config contains trailing data")
	}
	return nil
}

func loadRuntimeSigningEntity(path, fingerprint, address string, now time.Time) (*protonpgp.Entity, error) {
	raw, err := readProtectedFile(path, maxWebmailPrivateKeyBytes)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	var entities protonpgp.EntityList
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP")) {
		entities, err = protonpgp.ReadArmoredKeyRing(bytes.NewReader(trimmed))
	} else {
		entities, err = protonpgp.ReadKeyRing(bytes.NewReader(trimmed))
	}
	if err != nil {
		return nil, errors.New("parse webmail private key")
	}
	var matches []*protonpgp.Entity
	for _, entity := range entities {
		if entity != nil && entity.PrimaryKey != nil && strings.EqualFold(fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint), fingerprint) {
			matches = append(matches, entity)
		}
	}
	if len(matches) != 1 {
		return nil, errors.New("webmail signing fingerprint must match exactly one private entity")
	}
	entity := matches[0]
	if entity.Revoked(now) {
		return nil, errors.New("webmail signing key is revoked")
	}
	primarySig, _ := entity.PrimarySelfSignature()
	if primarySig == nil || entity.PrimaryKey.KeyExpired(primarySig, now) || primarySig.SigExpired(now) {
		return nil, errors.New("webmail signing key is expired or invalid")
	}
	identities := 0
	for _, identity := range entity.Identities {
		if identity == nil || identity.UserId == nil || !strings.EqualFold(strings.TrimSpace(identity.UserId.Email), address) {
			continue
		}
		identities++
		if identity.Revoked(now) || identity.SelfSignature == nil || identity.SelfSignature.SigExpired(now) {
			return nil, errors.New("webmail signing identity is revoked, disabled, or expired")
		}
	}
	if identities != 1 {
		return nil, errors.New("webmail sender must match exactly one signing identity")
	}
	if entity.PrivateKey == nil || entity.PrivateKey.Encrypted || entity.PrivateKey.Dummy() {
		return nil, errors.New("webmail primary private key is unavailable or locked")
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			return nil, errors.New("webmail signing subkey is locked")
		}
	}
	signingKey, ok := entity.SigningKey(now)
	if !ok || signingKey.PrivateKey == nil || signingKey.PrivateKey.Encrypted || signingKey.PrivateKey.Dummy() {
		return nil, errors.New("webmail usable private signing key required")
	}
	if err := ValidateOpenPGPMIMESHA256SigningKey(signingKey.PublicKey); err != nil {
		return nil, err
	}
	return entity, nil
}

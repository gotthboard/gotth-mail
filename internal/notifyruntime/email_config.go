package notifyruntime

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/webmail"
	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
)

const maxNotificationPrivateKeyBytes = 8 << 20

var (
	ErrSigningKeyMissing       = errors.New("signing_key_missing")
	ErrAmbiguousSigner         = errors.New(ReasonSigningIdentityAmbig)
	ErrSigningIdentityMismatch = errors.New("signing_identity_mismatch")
	ErrSigningKeyRevoked       = errors.New("signing_key_revoked")
	ErrSigningKeyExpired       = errors.New("signing_key_expired")
	ErrSigningIdentityDisabled = errors.New(ReasonSigningIdentityDisabled)
	ErrSigningKeyUnusable      = errors.New("signing_key_unusable")
	ErrSigningKeyEncrypted     = errors.New("signing_key_encrypted")
	ErrSigningHashUnsupported  = errors.New(ReasonSigningHashUnsupported)
)

type EmailConfig struct {
	From, To           string
	SigningFingerprint string
	PrivateKeyFile     string
	// SMTPAddr is a trusted local, plaintext relay endpoint. NetSMTPSubmitter
	// does not provide TLS or authentication, so public IPs and FQDNs are not
	// admissible here.
	SMTPAddr      string
	SMTPHelloName string
	SMTPTimeout   time.Duration
	Now           func() time.Time
	Policy        webmail.OutboundPolicyEvaluator
}

func NewSignedEmailBackend(c EmailConfig) (SignedEmailBackend, error) {
	from, err := configuredAddress("from", c.From)
	if err != nil {
		return SignedEmailBackend{}, err
	}
	to, err := configuredAddress("recipient", c.To)
	if err != nil {
		return SignedEmailBackend{}, err
	}
	fingerprint, err := configuredFingerprint(c.SigningFingerprint)
	if err != nil {
		return SignedEmailBackend{}, err
	}
	keyFile := strings.TrimSpace(c.PrivateKeyFile)
	if keyFile == "" {
		return SignedEmailBackend{}, errors.New("signed email private key file required")
	}
	if err := validateSMTPAddress(c.SMTPAddr); err != nil {
		return SignedEmailBackend{}, err
	}
	if c.Policy == nil {
		return SignedEmailBackend{}, errors.New("signed email outbound policy evaluator required")
	}
	clock := func() time.Time { return time.Now().UTC() }
	if c.Now != nil {
		clock = func() time.Time { return c.Now().UTC() }
	}
	material := &runtimeEmailMaterial{path: keyFile, fingerprint: fingerprint, from: from, clock: clock}
	if _, err := material.load(context.Background()); err != nil {
		return SignedEmailBackend{}, err
	}
	hello := strings.TrimSpace(c.SMTPHelloName)
	if hello == "" {
		hello = "gotth-mail-notification"
	}
	return SignedEmailBackend{
		From:               from,
		To:                 to,
		SigningFingerprint: fingerprint,
		SMTP:               webmail.NetSMTPSubmitter{Addr: strings.TrimSpace(c.SMTPAddr), HelloName: hello, Timeout: c.SMTPTimeout},
		Signer:             material,
		Verifier:           material,
		Resolver:           material,
		Policy:             c.Policy,
		Now:                clock,
	}, nil
}

type runtimeEmailMaterial struct {
	path, fingerprint, from string
	clock                   func() time.Time
}

func (m *runtimeEmailMaterial) load(ctx context.Context) (*protonpgp.Entity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return loadNotificationSigningEntity(m.path, m.fingerprint, m.from, m.clock().UTC())
}

func (m *runtimeEmailMaterial) ResolveSender(ctx context.Context, fingerprint, from, sender string) (webmail.Identity, error) {
	if err := ctx.Err(); err != nil {
		return webmail.Identity{}, err
	}
	if strings.TrimSpace(sender) != "" || !strings.EqualFold(strings.TrimSpace(fingerprint), m.fingerprint) || !strings.EqualFold(strings.TrimSpace(from), m.from) {
		return webmail.Identity{}, &IdentityResolutionError{Code: ReasonSigningIdentityMismatch, Err: ErrSigningIdentityMismatch}
	}
	if _, err := m.load(ctx); err != nil {
		return webmail.Identity{}, runtimeIdentityResolutionError(err)
	}
	return webmail.Identity{Address: m.from, Fingerprint: m.fingerprint}, nil
}

func (m *runtimeEmailMaterial) SignMIME(ctx context.Context, identity webmail.Identity, msg []byte) ([]byte, webmail.SignatureStatus, error) {
	entity, err := m.load(ctx)
	if err != nil {
		if errors.Is(err, ErrSigningHashUnsupported) {
			return nil, webmail.SignatureStatus{}, ErrSigningHashUnsupported
		}
		return nil, webmail.SignatureStatus{}, errors.New(ReasonOpenPGPSignFailed)
	}
	return (webmail.OpenPGPMIMESigner{Entity: entity, Now: m.clock}).SignMIME(ctx, identity, msg)
}

func (m *runtimeEmailMaterial) VerifyExactSender(ctx context.Context, signed []byte, identity webmail.Identity) (webmail.SignatureStatus, error) {
	entity, err := m.load(ctx)
	if err != nil {
		return webmail.SignatureStatus{}, errors.New(ReasonOpenPGPVerifyFailed)
	}
	return (webmail.OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: m.clock}).VerifyExactSender(ctx, signed, identity)
}

func runtimeIdentityResolutionError(err error) error {
	code := ReasonSigningKeyMissing
	switch {
	case errors.Is(err, ErrAmbiguousSigner):
		code = ReasonSigningIdentityAmbig
	case errors.Is(err, ErrSigningIdentityMismatch):
		code = ReasonSigningIdentityMismatch
	case errors.Is(err, ErrSigningKeyRevoked):
		code = ReasonSigningKeyRevoked
	case errors.Is(err, ErrSigningKeyExpired):
		code = ReasonSigningKeyExpired
	case errors.Is(err, ErrSigningIdentityDisabled):
		code = ReasonSigningIdentityDisabled
	case errors.Is(err, ErrSigningHashUnsupported):
		code = ReasonSigningHashUnsupported
	}
	return &IdentityResolutionError{Code: code, Err: errors.New(code)}
}

func configuredAddress(kind, raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("signed email %s required", kind)
	}
	parsed, err := mail.ParseAddress(raw)
	if err != nil || !asciiEmailAddress(parsed.Address) {
		return "", fmt.Errorf("valid signed email %s required", kind)
	}
	return strings.ToLower(parsed.Address), nil
}

func configuredFingerprint(raw string) (string, error) {
	fingerprint := strings.ToUpper(strings.TrimSpace(raw))
	if len(fingerprint) != 40 && len(fingerprint) != 64 {
		return "", errors.New("valid signed email signing fingerprint required")
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return "", errors.New("valid signed email signing fingerprint required")
	}
	return fingerprint, nil
}

func validateSMTPAddress(raw string) error {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return errors.New("signed email smtp address required")
	}
	host, port, err := net.SplitHostPort(addr)
	host = strings.TrimSpace(host)
	if err != nil || host == "" {
		return errors.New("valid signed email smtp host:port required")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("valid signed email smtp host:port required")
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() {
			return nil
		}
		return errors.New("signed email smtp must target a trusted local relay")
	}
	if !validLocalRelayName(host) {
		return errors.New("signed email smtp must target a trusted local relay")
	}
	return nil
}

func validLocalRelayName(host string) bool {
	// Single-label names are reserved here for local service discovery (for
	// example, the Compose service "postfix"); the local resolver remains part
	// of that trust boundary.
	if len(host) == 0 || len(host) > 63 || strings.Contains(host, ".") || host[0] == '-' || host[len(host)-1] == '-' {
		return false
	}
	hasLetter := false
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return hasLetter
}

func loadNotificationSigningEntity(path, fingerprint, from string, now time.Time) (*protonpgp.Entity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: private key file unavailable", ErrSigningKeyMissing)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: private key metadata unavailable", ErrSigningKeyMissing)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxNotificationPrivateKeyBytes {
		return nil, fmt.Errorf("%w: private key file must be a non-empty regular file no larger than %d bytes", ErrSigningKeyUnusable, maxNotificationPrivateKeyBytes)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: private key file must not be group/world accessible", ErrSigningKeyUnusable)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxNotificationPrivateKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: private key read failed", ErrSigningKeyUnusable)
	}
	entities, err := readNotificationKeyRing(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: private key parse failed", ErrSigningKeyUnusable)
	}
	var matches []*protonpgp.Entity
	for _, entity := range entities {
		if entity == nil || entity.PrimaryKey == nil {
			continue
		}
		got := strings.ToUpper(fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint))
		if got == fingerprint {
			matches = append(matches, entity)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: configured fingerprint not found", ErrSigningKeyMissing)
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("%w: configured fingerprint matched %d private entities", ErrAmbiguousSigner, len(matches))
	}
	if err := validateNotificationSigningEntity(matches[0], from, now); err != nil {
		return nil, err
	}
	return matches[0], nil
}

func readNotificationKeyRing(raw []byte) (protonpgp.EntityList, error) {
	trimmed := bytes.TrimSpace(raw)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP")) {
		return protonpgp.ReadArmoredKeyRing(bytes.NewReader(trimmed))
	}
	return protonpgp.ReadKeyRing(bytes.NewReader(trimmed))
}

func validateNotificationSigningEntity(entity *protonpgp.Entity, from string, now time.Time) error {
	if entity.PrimaryKey == nil {
		return fmt.Errorf("%w: primary key required", ErrSigningKeyUnusable)
	}
	if entity.Revoked(now) {
		return ErrSigningKeyRevoked
	}
	primarySig, primaryIdentity := entity.PrimarySelfSignature()
	if primarySig == nil {
		return fmt.Errorf("%w: primary self-signature required", ErrSigningKeyUnusable)
	}
	if entity.PrimaryKey.KeyExpired(primarySig, now) || primarySig.SigExpired(now) {
		return ErrSigningKeyExpired
	}
	if primaryIdentity != nil && primaryIdentity.Revoked(now) {
		return ErrSigningKeyRevoked
	}
	matchingIdentities := 0
	for _, identity := range entity.Identities {
		if identity == nil || identity.UserId == nil || !strings.EqualFold(strings.TrimSpace(identity.UserId.Email), from) {
			continue
		}
		matchingIdentities++
		if identity.Revoked(now) {
			return ErrSigningKeyRevoked
		}
		if identity.SelfSignature == nil {
			return ErrSigningIdentityDisabled
		}
		if identity.SelfSignature.SigExpired(now) {
			return ErrSigningKeyExpired
		}
	}
	if matchingIdentities == 0 {
		return fmt.Errorf("%w: configured sender is not bound to the signing key", ErrSigningIdentityMismatch)
	}
	if matchingIdentities != 1 {
		return fmt.Errorf("%w: configured sender matched %d key identities", ErrAmbiguousSigner, matchingIdentities)
	}
	if entity.PrivateKey == nil {
		return fmt.Errorf("%w: primary private key required", ErrSigningKeyMissing)
	}
	if entity.PrivateKey.Encrypted {
		return ErrSigningKeyEncrypted
	}
	if entity.PrivateKey.Dummy() {
		return fmt.Errorf("%w: dummy primary private key", ErrSigningKeyUnusable)
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			return ErrSigningKeyEncrypted
		}
	}
	signingKey, ok := entity.SigningKey(now)
	if !ok {
		return ErrSigningIdentityDisabled
	}
	if signingKey.PrivateKey == nil {
		return fmt.Errorf("%w: usable private signing key required", ErrSigningKeyMissing)
	}
	if signingKey.PrivateKey.Encrypted {
		return ErrSigningKeyEncrypted
	}
	if signingKey.PrivateKey.Dummy() {
		return fmt.Errorf("%w: dummy private signing key", ErrSigningKeyUnusable)
	}
	if err := webmail.ValidateOpenPGPMIMESHA256SigningKey(signingKey.PublicKey); err != nil {
		if errors.Is(err, webmail.ErrOpenPGPMIMEUnsupportedHash) {
			return ErrSigningHashUnsupported
		}
		return fmt.Errorf("%w: signing hash capability check failed", ErrSigningKeyUnusable)
	}
	return nil
}

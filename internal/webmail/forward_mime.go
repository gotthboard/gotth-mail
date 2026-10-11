package webmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/generatedmsgid"
)

// MaxForwardOriginalBytes is the forwarding-component capture ceiling: exact
// caller-supplied RFC5322 octets before any MIME wrapping. It is deliberately
// independent from the hostile-display parser's per-part limits.
const MaxForwardOriginalBytes = 50 << 20

// MaxForwardSignedBytes is the documented safe upper bound for the signed
// replacement produced from a MaxForwardOriginalBytes capture under the current
// fixed forwarding headers, MIME boundaries and detached-signature ceiling.
const MaxForwardSignedBytes = 72_796_392

const maxForwardMixedOverheadBytes = 1_557

// ForwardMessage is input from an already authorized forwarding caller.
// Identity, new MessageID and Date must not be inferred from the remote author.
// CapturedOriginal means exactly these bytes, not an attestation of SMTP wire
// serialization. The caller must not mutate the slice during Build.
type ForwardMessage struct {
	Identity         Identity
	CapturedOriginal []byte
	MessageID        string
	Date             time.Time
}

// SignedForwardBuilder has no delivery or context-authorization authority.
// Resolver must enforce configured active identity/key binding on every call.
// Its result does not replace future expansion/provenance and policy admission.
type SignedForwardBuilder struct {
	Resolver SenderIdentityResolver
	Signer   OpenPGPSigner
	Verifier ExactSenderVerifier
}

// Build returns only signed and verified new local-identity MIME. The opaque
// original is attached without parsing, normalization or authorship endorsement.
// All errors return nil bytes and empty status, never an unsigned intermediate.
// Complexity: on success, local MIME time and auxiliary space O(n+h+e),
// Omega(n+h+e), tight Theta(n+h+e), where n is bounded captured bytes, h is
// bounded metadata and e is base64+CRLF framing. Base64, multipart.Writer and
// bytes.Buffer allocate/copy linear output. Add resolver, signer and verifier
// times R,S,V and delegated peak auxiliary costs A: total time
// O(n+h+e+m+R+S+V), Omega(n+h+e+m+R+S+V), tight Theta under measured-call-cost
// variables; m is bounded signer output bytes scanned and optionally copied for
// CRLF. Auxiliary O(n+h+e+m+A), Omega(n+h+e+m), with no streaming claim.
// Existing crypto buffers/copies and key-file I/O are NOT constant or streaming.
// Early size rejection occurs before resolver/key I/O/sign/verify. Later
// cancellation/dependency failures have the same upper bound, Omega(1), and no
// uniform tight Theta across failure paths.
func (b SignedForwardBuilder) Build(ctx context.Context, request ForwardMessage) ([]byte, SignatureStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, SignatureStatus{}, err
	}
	if b.Resolver == nil || b.Signer == nil || b.Verifier == nil {
		return nil, SignatureStatus{}, errors.New("forward signing dependencies unavailable")
	}
	if len(request.CapturedOriginal) == 0 || len(request.CapturedOriginal) > MaxForwardOriginalBytes {
		return nil, SignatureStatus{}, errors.New("forward capture size invalid")
	}
	grow, ok := forwardMixedMessageBound(len(request.CapturedOriginal))
	if !ok || grow > MaxForwardSignedBytes {
		return nil, SignatureStatus{}, errors.New("forward capture size invalid")
	}
	address, err := exactEnvelopeAddress(request.Identity.Address)
	if err != nil || validHeaderValue(address) != nil {
		return nil, SignatureStatus{}, errors.New("forward identity address invalid")
	}
	fingerprint, err := canonicalRuntimeFingerprint(request.Identity.Fingerprint)
	if err != nil || fingerprint != request.Identity.Fingerprint {
		return nil, SignatureStatus{}, errors.New("forward identity fingerprint invalid")
	}
	id := request.MessageID
	if !validForwardMessageID(id) {
		return nil, SignatureStatus{}, errors.New("forward message id invalid")
	}
	date := request.Date.UTC()
	if request.Date.IsZero() || date.Year() < 1 || date.Year() > 9999 {
		return nil, SignatureStatus{}, errors.New("forward date invalid")
	}
	identity, err := b.Resolver.ResolveSender(ctx, fingerprint, address, "")
	if err != nil || identity.Address != address || identity.Fingerprint != fingerprint {
		return nil, SignatureStatus{}, errors.New("forward signing identity unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, SignatureStatus{}, err
	}

	// BuildMIME writes raw attachment bytes without transfer-encoding. Keep its
	// existing callers unchanged; this form requires opaque seven-bit attachment.
	var message bytes.Buffer
	message.Grow(grow)
	mixed := multipart.NewWriter(&message)
	fmt.Fprintf(&message, "From: %s\r\nReply-To: %s\r\nTo: undisclosed-recipients:;\r\nDate: %s\r\nMessage-ID: %s\r\nSubject: Forwarded message\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", address, address, date.Format(time.RFC1123Z), id, mixed.Boundary())
	text, err := mixed.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=us-ascii"}, "Content-Transfer-Encoding": {"7bit"}})
	if err != nil {
		return nil, SignatureStatus{}, errors.New("forward MIME construction failed")
	}
	// The writer is an owned bytes.Buffer: writes cannot return short/error.
	_, _ = text.Write([]byte("This local signature asserts forwarding responsibility, not original authorship.\r\nThe captured original is attached unchanged.\r\n"))
	attachment, err := mixed.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"application/octet-stream"},
		"Content-Disposition":       {"attachment; filename=original.eml"},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, SignatureStatus{}, errors.New("forward MIME construction failed")
	}
	var line [78]byte
	for remaining := request.CapturedOriginal; len(remaining) > 0; {
		if err := ctx.Err(); err != nil {
			return nil, SignatureStatus{}, err
		}
		n := min(len(remaining), 57)
		size := base64.StdEncoding.EncodedLen(n)
		base64.StdEncoding.Encode(line[:size], remaining[:n])
		line[size], line[size+1] = '\r', '\n'
		_, _ = attachment.Write(line[:size+2])
		remaining = remaining[n:]
	}
	if err := mixed.Close(); err != nil {
		return nil, SignatureStatus{}, errors.New("forward MIME construction failed")
	}
	if message.Len() > MaxForwardSignedBytes {
		return nil, SignatureStatus{}, errors.New("forward MIME construction failed")
	}
	signed, status, err := b.Signer.SignMIME(ctx, identity, message.Bytes())
	if err != nil || !status.Signed || status.Identity != address || status.Fingerprint != fingerprint || len(signed) == 0 || len(signed) > MaxForwardSignedBytes {
		return nil, SignatureStatus{}, errors.New("forward signing failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, SignatureStatus{}, err
	}
	// The existing signer emits LF in detached ASCII armor. Canonicalize wire
	// line endings before verification, preserving every already-CRLF byte.
	// This adds one bounded full-message copy, not a streaming claim. A signer
	// that signed noncanonical LF content will fail the subsequent verification.
	loneLF := 0
	for i, c := range signed {
		if c == '\n' && (i == 0 || signed[i-1] != '\r') {
			loneLF++
		}
	}
	if loneLF > MaxForwardSignedBytes-len(signed) {
		return nil, SignatureStatus{}, errors.New("forward signed output too large")
	}
	if loneLF != 0 {
		canonical := make([]byte, 0, len(signed)+loneLF)
		for i, c := range signed {
			if c == '\n' && (i == 0 || signed[i-1] != '\r') {
				canonical = append(canonical, '\r')
			}
			canonical = append(canonical, c)
		}
		signed = canonical
	}
	verified, err := b.Verifier.VerifyExactSender(ctx, signed, identity)
	if err != nil || !verified.Signed || verified.Identity != address || verified.Fingerprint != fingerprint {
		return nil, SignatureStatus{}, errors.New("forward verification failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, SignatureStatus{}, err
	}
	return signed, verified, nil
}

func forwardMixedMessageBound(n int) (int, bool) {
	encoded, ok := forwardBase64FramedBytes(int64(n))
	if !ok {
		return 0, false
	}
	if encoded > int64(^uint(0)>>1)-maxForwardMixedOverheadBytes {
		return 0, false
	}
	return int(encoded + maxForwardMixedOverheadBytes), true
}

func forwardBase64FramedBytes(n int64) (int64, bool) {
	if n < 0 {
		return 0, false
	}
	maxInt := int64(^uint(0) >> 1)
	groups := n / 3
	if n%3 != 0 {
		groups++
	}
	if groups > maxInt/4 {
		return 0, false
	}
	encoded := groups * 4
	lines := n / 57
	if n%57 != 0 {
		lines++
	}
	if lines > (maxInt-encoded)/2 {
		return 0, false
	}
	return encoded + lines*2, true
}

// validForwardMessageID admits only generated RFC5322 section3.6.4 IDs:
// <dot-atom-text@dot-atom-text>, ASCII atext, at most255 bytes including brackets.
// No CFWS, quoted/obsolete forms or domain literals; delegated to the shared generated-ID grammar.
// Time O(h), Omega(1), tight Theta(h); auxiliary O(1), Omega(1), tight Theta(1).
func validForwardMessageID(id string) bool { return generatedmsgid.Valid(id) }

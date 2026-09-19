package outboundpolicy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
)

const (
	defaultPostfixOutputBytes = 64 << 20
	maxPostfixOutputBytes     = 64 << 20
	maxPostqueueJSONLineBytes = 4 << 20
)

var errCommandOutputLimit = errors.New("command output limit exceeded")

type CommandRunner interface {
	Run(context.Context, string, []string, int) ([]byte, error)
}

type ExecCommandRunner struct{}

type PostfixBoundary struct {
	Runner         CommandRunner
	PostqueuePath  string
	PostsuperPath  string
	InstanceID     string
	MaxOutputBytes int
}

type postqueueRecipient struct {
	Address string `json:"address"`
}

type postqueueEntry struct {
	QueueName   string               `json:"queue_name"`
	QueueID     string               `json:"queue_id"`
	ArrivalTime int64                `json:"arrival_time"`
	MessageSize int64                `json:"message_size"`
	Sender      string               `json:"sender"`
	Recipients  []postqueueRecipient `json:"recipients"`
}

type boundedCommandOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

// Run executes one absolute binary directly with a fixed environment and a
// combined bounded stdout/stderr sink. It never invokes a shell.
// Complexity: time O(o), Omega(1), tight Theta(o); auxiliary space O(o),
// Omega(1), where o is output capped at maxOutput.
func (ExecCommandRunner) Run(ctx context.Context, path string, args []string, maxOutput int) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maxOutput <= 0 || maxOutput > maxPostfixOutputBytes {
		return nil, errors.New("invalid bounded command request")
	}
	sink := &boundedCommandOutput{limit: maxOutput}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	cmd.Stdout = sink
	cmd.Stderr = sink
	err := cmd.Run()
	output := append([]byte(nil), sink.buffer.Bytes()...)
	if sink.exceeded {
		return output, errCommandOutputLimit
	}
	if err != nil {
		return output, fmt.Errorf("bounded command failed: %w", err)
	}
	return output, nil
}

// Write retains at most the configured output bound and stops pipe copies as
// soon as the child exceeds it.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is bytes admitted before the fixed limit.
func (w *boundedCommandOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exceeded {
		return 0, errCommandOutputLimit
	}
	remaining := w.limit - w.buffer.Len()
	if len(p) <= remaining {
		return w.buffer.Write(p)
	}
	if remaining > 0 {
		_, _ = w.buffer.Write(p[:remaining])
	}
	w.exceeded = true
	return remaining, errCommandOutputLimit
}

// Inspect parses Postfix's documented JSON Lines queue format, accepts one
// stable observation of the requested long ID, and derives an arrival
// fingerprint that is unchanged by moves into the hold queue.
// Complexity: time O(o+r log r+b), Omega(o), tight Theta(o+r log r+b);
// auxiliary space O(o+r+b), Omega(1), where output o is bounded, r is bounded
// recipients, and b is their bytes.
func (b PostfixBoundary) Inspect(ctx context.Context, queueID string) (QueueMetadata, error) {
	if !validLongQueueID(queueID) || !validPostfixPath(b.PostqueuePath, "postqueue") {
		return QueueMetadata{}, errors.New("invalid Postfix queue inspection request")
	}
	instance, err := NormalizeDomain(b.InstanceID)
	if err != nil {
		return QueueMetadata{}, errors.New("invalid Postfix instance identity")
	}
	limit, err := b.outputLimit()
	if err != nil {
		return QueueMetadata{}, err
	}
	output, err := b.runner().Run(ctx, b.PostqueuePath, []string{"-j"}, limit)
	if err != nil {
		return QueueMetadata{}, errors.New("Postfix queue inspection failed")
	}
	if len(output) > limit {
		return QueueMetadata{}, errors.New("Postfix queue inspection output exceeded limit")
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64<<10), maxPostqueueJSONLineBytes)
	var found *QueueMetadata
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var entry postqueueEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return QueueMetadata{}, errors.New("invalid Postfix JSON queue output")
		}
		if entry.QueueID != queueID {
			continue
		}
		metadata, err := queueMetadataFromEntry(instance, entry)
		if err != nil {
			return QueueMetadata{}, err
		}
		if found != nil && !equalQueueMetadata(*found, metadata) {
			return QueueMetadata{}, errors.New("Postfix queue metadata changed during inspection")
		}
		found = &metadata
	}
	if err := scanner.Err(); err != nil {
		return QueueMetadata{}, errors.New("Postfix queue inspection output exceeded line limit")
	}
	if found == nil {
		return QueueMetadata{}, errors.New("Postfix queue ID not found")
	}
	return *found, nil
}

// Hold invokes only the documented whole-message `postsuper -h queue_id`
// operation with one previously validated long queue ID.
// Complexity: time O(o), Omega(1), tight Theta(o); auxiliary space O(o),
// Omega(1), where bounded o is helper output; process latency is additive.
func (b PostfixBoundary) Hold(ctx context.Context, queueID string) error {
	if !validLongQueueID(queueID) || !validPostfixPath(b.PostsuperPath, "postsuper") {
		return errors.New("invalid Postfix hold request")
	}
	limit, err := b.outputLimit()
	if err != nil {
		return err
	}
	if _, err := b.runner().Run(ctx, b.PostsuperPath, []string{"-h", queueID}, limit); err != nil {
		return errors.New("Postfix hold helper failed")
	}
	return nil
}

// Release invokes only the documented whole-message `postsuper -H queue_id`
// operation with one previously validated long queue ID.
// Complexity: time O(o), Omega(1), tight Theta(o); auxiliary space O(o),
// Omega(1), where bounded o is helper output; process latency is additive.
func (b PostfixBoundary) Release(ctx context.Context, queueID string) error {
	if !validLongQueueID(queueID) || !validPostfixPath(b.PostsuperPath, "postsuper") {
		return errors.New("invalid Postfix release request")
	}
	limit, err := b.outputLimit()
	if err != nil {
		return err
	}
	if _, err := b.runner().Run(ctx, b.PostsuperPath, []string{"-H", queueID}, limit); err != nil {
		return errors.New("Postfix release helper failed")
	}
	return nil
}

// QueueArrivalFingerprint binds the Postfix instance, long ID, arrival time,
// message size, canonical envelope sender, and canonical recipient set.
// Complexity: time O(r log r+b), Omega(r), tight Theta(r log r+b); auxiliary
// space O(r+b), Omega(r), where r is bounded recipients and b is their bytes.
func QueueArrivalFingerprint(instanceID, queueID string, arrivalTime, messageSize int64, sender string, recipients []string) (string, error) {
	instance, err := NormalizeDomain(instanceID)
	if err != nil || !validLongQueueID(queueID) || arrivalTime < 0 || messageSize < 0 {
		return "", errors.New("invalid Postfix arrival identity")
	}
	canonicalSender, err := normalizePostqueueSender(sender)
	if err != nil {
		return "", err
	}
	canonicalRecipients, err := canonicalQueueRecipients(recipients)
	if err != nil {
		return "", err
	}
	values := make([]string, 0, 6+len(canonicalRecipients))
	values = append(values, "gotth-mail/postfix-arrival/v1", instance, queueID, strconv.FormatInt(arrivalTime, 10), strconv.FormatInt(messageSize, 10), canonicalSender)
	values = append(values, canonicalRecipients...)
	return digestStrings(values), nil
}

// queueMetadataFromEntry validates one target JSON object and derives its
// canonical inspection result.
// Complexity: time O(r log r+b), Omega(r), tight Theta(r log r+b); auxiliary
// space O(r+b), Omega(r), with QueueArrivalFingerprint variables.
func queueMetadataFromEntry(instance string, entry postqueueEntry) (QueueMetadata, error) {
	if !validLongQueueID(entry.QueueID) || entry.ArrivalTime < 0 || entry.MessageSize < 0 {
		return QueueMetadata{}, errors.New("invalid Postfix queue identity")
	}
	held := false
	switch entry.QueueName {
	case "incoming", "active", "deferred":
	case "hold":
		held = true
	default:
		return QueueMetadata{}, errors.New("unsupported Postfix queue state")
	}
	sender, err := normalizePostqueueSender(entry.Sender)
	if err != nil {
		return QueueMetadata{}, err
	}
	recipients := make([]string, 0, len(entry.Recipients))
	for _, recipient := range entry.Recipients {
		recipients = append(recipients, recipient.Address)
	}
	recipients, err = canonicalQueueRecipients(recipients)
	if err != nil {
		return QueueMetadata{}, err
	}
	fingerprint, err := QueueArrivalFingerprint(instance, entry.QueueID, entry.ArrivalTime, entry.MessageSize, sender, recipients)
	if err != nil {
		return QueueMetadata{}, err
	}
	return QueueMetadata{QueueID: entry.QueueID, ArrivalFingerprint: fingerprint, EnvelopeSender: sender, Recipients: recipients, Held: held}, nil
}

// canonicalQueueRecipients returns one sorted exact-domain-normalized set.
// Complexity: time O(r log r+b), Omega(r), tight Theta(r log r+b); auxiliary
// space O(r+b), Omega(r), where r is bounded recipients and b is their bytes.
func canonicalQueueRecipients(recipients []string) ([]string, error) {
	if len(recipients) == 0 || len(recipients) > maxQueueRecipients {
		return nil, errors.New("Postfix queue recipient limit violated")
	}
	set := make(map[string]struct{}, len(recipients))
	for _, raw := range recipients {
		recipient, _, err := normalizeQueueRecipient(raw)
		if err != nil {
			return nil, err
		}
		set[recipient] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for recipient := range set {
		result = append(result, recipient)
	}
	sort.Strings(result)
	return result, nil
}

// normalizePostqueueSender maps Postfix's empty JSON sender to the SMTP null
// reverse path and otherwise canonicalizes an envelope address.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is the bounded sender length.
func normalizePostqueueSender(sender string) (string, error) {
	if sender == "" {
		return "<>", nil
	}
	return normalizeQueueSender(sender)
}

// equalQueueMetadata compares one bounded canonical observation.
// Complexity: time O(r*b), Omega(1), tight Theta(r*b) for equal observations;
// auxiliary space O(1), Omega(1), where r is recipients and b address length.
func equalQueueMetadata(left, right QueueMetadata) bool {
	if left.QueueID != right.QueueID || left.ArrivalFingerprint != right.ArrivalFingerprint || left.EnvelopeSender != right.EnvelopeSender || left.Held != right.Held || len(left.Recipients) != len(right.Recipients) {
		return false
	}
	for i := range left.Recipients {
		if left.Recipients[i] != right.Recipients[i] {
			return false
		}
	}
	return true
}

// outputLimit applies the fixed process-output ceiling.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func (b PostfixBoundary) outputLimit() (int, error) {
	if b.MaxOutputBytes == 0 {
		return defaultPostfixOutputBytes, nil
	}
	if b.MaxOutputBytes < 1 || b.MaxOutputBytes > maxPostfixOutputBytes {
		return 0, errors.New("invalid Postfix output limit")
	}
	return b.MaxOutputBytes, nil
}

// runner supplies the real bounded executor unless a test/runtime adapter was
// explicitly injected.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func (b PostfixBoundary) runner() CommandRunner {
	if b.Runner != nil {
		return b.Runner
	}
	return ExecCommandRunner{}
}

// validPostfixPath restricts command selection to one absolute expected binary
// basename; operation flags remain fixed by the caller.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is the bounded configured path length.
func validPostfixPath(path, base string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) == base
}

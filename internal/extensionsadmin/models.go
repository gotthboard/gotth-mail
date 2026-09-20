package extensionsadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MetadataSchema = "gotth.mail.extension.config.v1"
	Product        = "gotth-mail"

	maxMetadataBytes = 64 << 10
	maxFields        = 64
	maxConfigBytes   = 64 << 10
	maxSecretBytes   = 4096
)

type FieldKind string

const (
	FieldString  FieldKind = "string"
	FieldInteger FieldKind = "integer"
	FieldBoolean FieldKind = "boolean"
	FieldEnum    FieldKind = "enum"
	FieldSecret  FieldKind = "secret"
)

type Field struct {
	Name     string    `json:"name"`
	Label    string    `json:"label"`
	Kind     FieldKind `json:"kind"`
	Required bool      `json:"required,omitempty"`
	Min      *int64    `json:"min,omitempty"`
	Max      *int64    `json:"max,omitempty"`
	Default  any       `json:"default,omitempty"`
	Options  []string  `json:"options,omitempty"`
}

type Metadata struct {
	Schema string  `json:"schema"`
	Fields []Field `json:"fields"`
}

type SecretStatus struct {
	Slot       string    `json:"slot"`
	Configured bool      `json:"configured"`
	RotatedAt  time.Time `json:"rotated_at,omitempty"`
}

type Instance struct {
	InstanceID        string         `json:"instance_id"`
	Product           string         `json:"product"`
	ExtensionID       string         `json:"extension_id"`
	Repository        string         `json:"repository"`
	ArtifactPin       string         `json:"artifact_pin"`
	PreviousArtifact  string         `json:"previous_artifact_pin,omitempty"`
	AvailableUpdate   string         `json:"available_update_pin,omitempty"`
	ManifestDigest    string         `json:"manifest_sha256"`
	GrantDigest       string         `json:"grant_sha256"`
	SessionDigest     string         `json:"session_sha256"`
	Capabilities      []string       `json:"capabilities"`
	Interfaces        []string       `json:"interfaces"`
	SecretSlots       []string       `json:"secret_slots"`
	Metadata          Metadata       `json:"metadata"`
	Configuration     map[string]any `json:"configuration"`
	ConfigurationRev  int64          `json:"configuration_revision"`
	Lifecycle         string         `json:"lifecycle"`
	HealthCode        string         `json:"health_code"`
	TestedRevision    int64          `json:"tested_revision,omitempty"`
	Enabled           bool           `json:"enabled"`
	Routed            bool           `json:"routed"`
	LastCorrelationID string         `json:"last_correlation_id,omitempty"`
	Secrets           []SecretStatus `json:"secrets"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

type InstallRequest struct {
	InstanceID      string   `json:"instance_id"`
	ExtensionID     string   `json:"extension_id"`
	Repository      string   `json:"repository"`
	ArtifactPin     string   `json:"artifact_pin"`
	ManifestDigest  string   `json:"manifest_sha256"`
	GrantDigest     string   `json:"grant_sha256"`
	SessionDigest   string   `json:"session_sha256"`
	Capabilities    []string `json:"capabilities"`
	Interfaces      []string `json:"interfaces"`
	SecretSlots     []string `json:"secret_slots"`
	Metadata        Metadata `json:"metadata"`
	AvailableUpdate string   `json:"available_update_pin,omitempty"`
	CorrelationID   string   `json:"correlation_id,omitempty"`
}

type ConfigureInput struct {
	Configuration map[string]any    `json:"configuration"`
	Secrets       map[string]string `json:"secrets,omitempty"`
}

type UpdateInput struct {
	ArtifactPin    string   `json:"artifact_pin"`
	ManifestDigest string   `json:"manifest_sha256"`
	GrantDigest    string   `json:"grant_sha256"`
	SessionDigest  string   `json:"session_sha256"`
	Capabilities   []string `json:"capabilities"`
	Interfaces     []string `json:"interfaces"`
	SecretSlots    []string `json:"secret_slots"`
	Metadata       Metadata `json:"metadata"`
}

type Preview struct {
	ID                string    `json:"id"`
	InstanceID        string    `json:"instance_id"`
	Operation         string    `json:"operation"`
	BaseRevision      int64     `json:"base_revision"`
	PayloadSHA256     string    `json:"payload_sha256"`
	Confirmation      string    `json:"confirmation"`
	PrivilegeDiff     []string  `json:"privilege_diff"`
	ConfigurationDiff []string  `json:"configuration_diff"`
	SecretSlotDiff    []string  `json:"secret_slot_diff"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type Health struct {
	Healthy bool
	Code    string
}

type Runtime interface {
	Start(ctx context.Context, instance Instance, secrets map[string][]byte) error
	Probe(ctx context.Context, instance Instance) (Health, error)
	AdmitRouting(ctx context.Context, instance Instance) error
	RevokeRouting(ctx context.Context, instance Instance) error
	Stop(ctx context.Context, instance Instance) error
}

var (
	ErrUnavailable     = errors.New("extension administrator unavailable")
	ErrNotFound        = errors.New("extension instance not found")
	ErrConflict        = errors.New("extension state conflict")
	ErrConfirmation    = errors.New("extension confirmation rejected")
	ErrUnauthenticated = errors.New("extension runtime unauthenticated")
	ErrUnhealthy       = errors.New("extension runtime unhealthy")
)

func DecodeMetadata(data []byte) (Metadata, error) {
	if len(data) == 0 || len(data) > maxMetadataBytes {
		return Metadata{}, errors.New("bounded extension metadata required")
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		return Metadata{}, errors.New("invalid extension metadata")
	}
	var metadata Metadata
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&metadata); err != nil {
		return Metadata{}, errors.New("invalid extension metadata")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Metadata{}, errors.New("invalid extension metadata")
	}
	if err := ValidateMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func ValidateMetadata(metadata Metadata) error {
	if metadata.Schema != MetadataSchema || len(metadata.Fields) > maxFields {
		return errors.New("invalid extension metadata")
	}
	seen := make(map[string]bool, len(metadata.Fields))
	for _, field := range metadata.Fields {
		if !validDottedToken(field.Name) || !validLabel(field.Label) || seen[field.Name] {
			return errors.New("invalid extension metadata field")
		}
		seen[field.Name] = true
		switch field.Kind {
		case FieldString:
			if len(field.Options) != 0 || field.Min != nil && (*field.Min < 0 || *field.Min > 4096) || field.Max != nil && (*field.Max < 0 || *field.Max > 4096) || field.Min != nil && field.Max != nil && *field.Min > *field.Max {
				return errors.New("invalid string metadata field")
			}
		case FieldInteger:
			if len(field.Options) != 0 || field.Min != nil && field.Max != nil && *field.Min > *field.Max {
				return errors.New("invalid integer metadata field")
			}
		case FieldBoolean:
			if len(field.Options) != 0 || field.Min != nil || field.Max != nil {
				return errors.New("invalid boolean metadata field")
			}
		case FieldEnum:
			if len(field.Options) < 1 || len(field.Options) > 64 || field.Min != nil || field.Max != nil {
				return errors.New("invalid enum metadata field")
			}
			options := map[string]bool{}
			for _, option := range field.Options {
				if !validScalarText(option, 128) || options[option] {
					return errors.New("invalid enum metadata field")
				}
				options[option] = true
			}
		case FieldSecret:
			if field.Default != nil || len(field.Options) != 0 || field.Min != nil || field.Max != nil {
				return errors.New("invalid secret metadata field")
			}
		default:
			return errors.New("unknown extension metadata field kind")
		}
		if field.Default != nil {
			if err := validateFieldValue(field, field.Default); err != nil {
				return errors.New("invalid extension metadata default")
			}
		}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil || len(encoded) > maxMetadataBytes {
		return errors.New("extension metadata exceeds limit")
	}
	return nil
}

func ValidateConfiguration(metadata Metadata, configuration map[string]any, secretSlots []string) ([]byte, error) {
	if err := ValidateMetadata(metadata); err != nil {
		return nil, err
	}
	if configuration == nil {
		configuration = map[string]any{}
	}
	fields := make(map[string]Field, len(metadata.Fields))
	slots := make(map[string]bool, len(secretSlots))
	for _, slot := range secretSlots {
		slots[slot] = true
	}
	for _, field := range metadata.Fields {
		fields[field.Name] = field
		if field.Kind == FieldSecret && !slots[field.Name] {
			return nil, errors.New("metadata secret slot not granted")
		}
	}
	for name, value := range configuration {
		field, ok := fields[name]
		if !ok || field.Kind == FieldSecret {
			return nil, errors.New("configuration contains unknown or secret field")
		}
		if err := validateFieldValue(field, value); err != nil {
			return nil, err
		}
	}
	for _, field := range metadata.Fields {
		if field.Kind != FieldSecret && field.Required {
			if _, ok := configuration[field.Name]; !ok && field.Default == nil {
				return nil, fmt.Errorf("required configuration field missing")
			}
		}
	}
	encoded, err := json.Marshal(configuration)
	if err != nil || len(encoded) > maxConfigBytes {
		return nil, errors.New("configuration exceeds limit")
	}
	return encoded, nil
}

func validateFieldValue(field Field, value any) error {
	switch field.Kind {
	case FieldString:
		text, ok := value.(string)
		if !ok || !validScalarText(text, 4096) {
			return errors.New("invalid string configuration")
		}
		length := int64(len(text))
		if field.Min != nil && length < *field.Min || field.Max != nil && length > *field.Max {
			return errors.New("string configuration outside bounds")
		}
	case FieldInteger:
		number, ok := integerValue(value)
		if !ok || field.Min != nil && number < *field.Min || field.Max != nil && number > *field.Max {
			return errors.New("invalid integer configuration")
		}
	case FieldBoolean:
		if _, ok := value.(bool); !ok {
			return errors.New("invalid boolean configuration")
		}
	case FieldEnum:
		text, ok := value.(string)
		if !ok {
			return errors.New("invalid enum configuration")
		}
		for _, option := range field.Options {
			if text == option {
				return nil
			}
		}
		return errors.New("invalid enum configuration")
	case FieldSecret:
		return errors.New("secret values require the write-only secret channel")
	default:
		return errors.New("unknown configuration field")
	}
	return nil
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case json.Number:
		n, err := strconv.ParseInt(string(typed), 10, 64)
		return n, err == nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || typed < math.MinInt64 || typed > math.MaxInt64 || math.Trunc(typed) != typed {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}

func validLabel(value string) bool {
	lower := strings.ToLower(value)
	if !validScalarText(value, 128) || strings.ContainsAny(value, "<>&") || strings.Contains(lower, "://") || strings.Contains(lower, "javascript:") || strings.Contains(lower, "data:") {
		return false
	}
	return true
}

func validScalarText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validDottedToken(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 || part[0] < 'a' || part[0] > 'z' || part[len(part)-1] == '-' {
			return false
		}
		for _, char := range part {
			if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func canonicalTokens(values []string) ([]string, error) {
	result := append([]string(nil), values...)
	sort.Strings(result)
	for i, value := range result {
		if !validDottedToken(value) || i > 0 && value == result[i-1] {
			return nil, errors.New("invalid or duplicate extension token")
		}
	}
	return result, nil
}

func rejectDuplicateJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok || seen[name] {
				return errors.New("duplicate JSON name")
			}
			seen[name] = true
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}

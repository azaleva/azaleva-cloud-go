package cloud

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TemplatesService reads templates and publishes the consumer's recipe template packages.
type TemplatesService struct{ c *Client }

// TemplateListOptions filter templates.
type TemplateListOptions struct {
	Kind   TemplateKind
	Name   string
	Limit  int
	Cursor string
}

// List lists built-in templates and the consumer's own.
func (s *TemplatesService) List(ctx context.Context, o TemplateListOptions) (*Page[Template], error) {
	q := ListOptions{Limit: o.Limit, Cursor: o.Cursor}.values()
	if o.Kind != "" {
		q.Set("kind", string(o.Kind))
	}
	if o.Name != "" {
		q.Set("name", o.Name)
	}
	var out Page[Template]
	return &out, s.c.call(ctx, http.MethodGet, "/templates", q, nil, &out)
}

// Get returns a template ("tpl_name@3", "name@3" or "name").
func (s *TemplatesService) Get(ctx context.Context, ref string) (*Template, error) {
	path, err := p("templates", ref)
	if err != nil {
		return nil, err
	}
	var out Template
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// Delete deletes one of the consumer's template versions ("name@3"). It is refused (409
// conflict) while the version is pinned or a machine or job uses it. The version keeps its
// package and builds for the installation's grace period (7 days by default) and can be
// brought back with Restore meanwhile; with WithPurge it is purged at once instead (no
// restore; its builds become reclaimable by the next storage_gc), also when it was deleted
// before and is still within its grace period.
func (s *TemplatesService) Delete(ctx context.Context, ref string, opts ...CallOption) error {
	path, err := p("templates", ref)
	if err != nil {
		return err
	}
	var cfg callConfig
	for _, o := range opts {
		o(&cfg)
	}
	var q url.Values
	if cfg.purge {
		q = url.Values{"purge": {"true"}}
	}
	return s.c.call(ctx, http.MethodDelete, path, q, nil, nil, opts...)
}

// WithPurge makes Templates.Delete purge the version: no grace period, no restore.
func WithPurge() CallOption { return func(c *callConfig) { c.purge = true } }

// Pin pins one of the consumer's template versions ("name@3"): it cannot be deleted, or pruned
// by template_versions_kept, until Unpin. Idempotent; it returns the version.
func (s *TemplatesService) Pin(ctx context.Context, ref string, opts ...CallOption) (*Template, error) {
	path, err := p("templates", ref)
	if err != nil {
		return nil, err
	}
	var out Template
	return &out, s.c.call(ctx, http.MethodPut, path+"/pin", nil, nil, &out, opts...)
}

// Unpin unpins a template version. Idempotent; it returns the version.
func (s *TemplatesService) Unpin(ctx context.Context, ref string, opts ...CallOption) (*Template, error) {
	path, err := p("templates", ref)
	if err != nil {
		return nil, err
	}
	var out Template
	return &out, s.c.call(ctx, http.MethodDelete, path+"/pin", nil, nil, &out, opts...)
}

// Restore brings back a template version deleted within the grace period, in the state it had
// (its builds are still on the nodes). A version that is not deleted is returned as it is; one
// whose grace period ended, or that was purged, answers 410 gone.
func (s *TemplatesService) Restore(ctx context.Context, ref string, opts ...CallOption) (*Template, error) {
	path, err := p("templates", ref)
	if err != nil {
		return nil, err
	}
	var out Template
	return &out, s.c.call(ctx, http.MethodPost, path+"/restore", nil, nil, &out, opts...)
}

// BuildLog returns the build log of a template on a node.
func (s *TemplatesService) BuildLog(ctx context.Context, ref, node string) (string, error) {
	path, err := p("templates", ref, "builds", node)
	if err != nil {
		return "", err
	}
	r := &request{method: http.MethodGet, path: path + "/log", accept: "text/plain"}
	resp, err := s.c.do(ctx, r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// Upload publishes a signed recipe template package (see BuildTemplatePackage and
// SignTemplatePackage). An identical package returns the existing version (status 200).
func (s *TemplatesService) Upload(ctx context.Context, pkg []byte, sig TemplateSignature, opts ...CallOption) (*Template, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("package", "template.tar.gz")
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(pkg); err != nil {
		return nil, err
	}
	if err := mw.WriteField("signature", sig.Signature); err != nil {
		return nil, err
	}
	if err := mw.WriteField("key_id", sig.KeyID); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	r := &request{method: http.MethodPost, path: "/templates", body: buf.Bytes(), ctype: mw.FormDataContentType(), accept: "application/json"}
	resp, err := s.c.do(ctx, r, opts...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out Template
	return &out, json.NewDecoder(resp.Body).Decode(&out)
}

// TemplateManifest is template.json, the first entry of a recipe template package.
type TemplateManifest struct {
	// Name is the template name ([a-z][a-z0-9-]{0,62}); versions are assigned by Azaleva Cloud.
	Name string `json:"name"`
	// Kind is job or machine.
	Kind TemplateKind `json:"kind"`
	// Recipe is the entry point in the package (Python calling the pinned template SDK).
	Recipe string `json:"recipe"`
	// SDK is the template SDK pin (the installation documents it; a built-in template's
	// Template.SDK shows the current one). See the Azaleva Cloud documentation.
	SDK         string `json:"sdk"`
	Description string `json:"description,omitempty"`
	// Services are the guest services machines of this template run, reachable through the
	// transport under policy app (machine templates only; ValidateServiceDeclarations).
	Services []ServiceDeclaration `json:"services,omitempty"`
}

// TemplateSignature is a package's detached signature.
type TemplateSignature struct {
	KeyID     string // see KeyID
	Signature string // base64 Ed25519 signature
}

// Package limits.
const (
	TemplatePackageMaxBytes = 256 << 20
	templateManifestName    = "template.json"
	templateSignaturePrefix = "agent-cloud template package v1\n"
)

var templateNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// ValidTemplateName reports whether name is a valid template name.
func ValidTemplateName(name string) bool { return templateNameRE.MatchString(name) }

// BuildTemplatePackage writes a deterministic package: template.json first, then files in
// sorted order, with fixed timestamps and modes, so equal inputs give equal bytes (and the
// same recipe hash).
func BuildTemplatePackage(m TemplateManifest, files map[string][]byte) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	if _, ok := files[m.Recipe]; !ok {
		return nil, fmt.Errorf("cloud: recipe %q is not among the files", m.Recipe)
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		if err := checkPackagePath(n); err != nil {
			return nil, err
		}
		if n == templateManifestName {
			return nil, fmt.Errorf("cloud: %s is generated from the manifest", templateManifestName)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	gz.ModTime = time.Unix(0, 0)
	tw := tar.NewWriter(gz)
	write := func(name string, b []byte) error {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := write(templateManifestName, mb); err != nil {
		return nil, err
	}
	for _, n := range names {
		if err := write(n, files[n]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m TemplateManifest) validate() error {
	var errs []string
	if !ValidTemplateName(m.Name) {
		errs = append(errs, "name must match [a-z][a-z0-9-]{0,62}")
	}
	if m.Kind != KindJob && m.Kind != KindMachine {
		errs = append(errs, "kind must be job or machine")
	}
	if m.Recipe == "" || checkPackagePath(m.Recipe) != nil {
		errs = append(errs, "recipe must be a relative path in the package")
	}
	if m.SDK == "" {
		errs = append(errs, "sdk (the template SDK pin) is required")
	}
	if len(errs) > 0 {
		return fmt.Errorf("cloud: invalid template manifest: %s", strings.Join(errs, "; "))
	}
	return nil
}

func checkPackagePath(n string) error {
	if n == "" || strings.HasPrefix(n, "/") || path.Clean(n) != n || n == ".." || strings.HasPrefix(n, "../") {
		return fmt.Errorf("cloud: invalid package path %q", n)
	}
	return nil
}

// ReadTemplatePackage parses and validates a package (for servers and fakes).
func ReadTemplatePackage(pkg []byte) (*TemplateManifest, map[string][]byte, error) {
	if len(pkg) > TemplatePackageMaxBytes {
		return nil, nil, errors.New("package too large")
	}
	gz, err := gzip.NewReader(bytes.NewReader(pkg))
	if err != nil {
		return nil, nil, fmt.Errorf("not gzip: %w", err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var manifest *TemplateManifest
	var total int64
	for i := 0; ; i++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("bad tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, nil, fmt.Errorf("unsupported entry type for %q", hdr.Name)
		}
		if err := checkPackagePath(hdr.Name); err != nil {
			return nil, nil, err
		}
		total += hdr.Size
		if total > TemplatePackageMaxBytes {
			return nil, nil, errors.New("package too large")
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, nil, err
		}
		if hdr.Name == templateManifestName {
			if i != 0 {
				return nil, nil, errors.New("template.json must be the first entry")
			}
			var m TemplateManifest
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&m); err != nil {
				return nil, nil, fmt.Errorf("template.json: %w", err)
			}
			manifest = &m
			continue
		}
		files[hdr.Name] = b
	}
	if manifest == nil {
		return nil, nil, errors.New("template.json is missing")
	}
	if err := manifest.validate(); err != nil {
		return nil, nil, err
	}
	if _, ok := files[manifest.Recipe]; !ok {
		return nil, nil, fmt.Errorf("recipe %q is missing", manifest.Recipe)
	}
	return manifest, files, nil
}

// TemplatePackageHash is the recipe hash: hex SHA-256 of the package bytes.
func TemplatePackageHash(pkg []byte) string {
	h := sha256.Sum256(pkg)
	return hex.EncodeToString(h[:])
}

// KeyID is a public key's ID: "ed25519:" + the first 16 hex characters of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(h[:8])
}

func templateSignedMessage(pkg []byte) []byte {
	return []byte(templateSignaturePrefix + TemplatePackageHash(pkg))
}

// SignTemplatePackage signs a package with a consumer's template signing key.
func SignTemplatePackage(priv ed25519.PrivateKey, pkg []byte) TemplateSignature {
	pub := priv.Public().(ed25519.PublicKey)
	return TemplateSignature{KeyID: KeyID(pub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, templateSignedMessage(pkg)))}
}

// VerifyTemplatePackage checks a package's signature against a registered public key.
func VerifyTemplatePackage(pub ed25519.PublicKey, pkg []byte, signature string) error {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("signature is not base64 Ed25519")
	}
	if !ed25519.Verify(pub, templateSignedMessage(pkg), sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// TemplateNameAllowed reports whether name matches one of a signer's allowed names
// (exact, or a prefix with a trailing "*").
func TemplateNameAllowed(patterns []string, name string) bool {
	for _, p := range patterns {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(name, strings.TrimSuffix(p, "*")) {
				return true
			}
		} else if p == name {
			return true
		}
	}
	return false
}

// ParseTemplateRef splits "tpl_name@3", "name@3" or "name" into name and version (0 = newest).
func ParseTemplateRef(ref string) (name string, version int, err error) {
	ref = strings.TrimPrefix(ref, "tpl_")
	name, v, found := strings.Cut(ref, "@")
	if !ValidTemplateName(name) {
		return "", 0, fmt.Errorf("invalid template reference %q", ref)
	}
	if !found {
		return name, 0, nil
	}
	version, err = strconv.Atoi(v)
	if err != nil || version < 1 {
		return "", 0, fmt.Errorf("invalid template version in %q", ref)
	}
	return name, version, nil
}

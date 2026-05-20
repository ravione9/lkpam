// Package saml is the SAML 2.0 Service Provider for portal SSO. It works with
// any standards-compliant IdP — Google Workspace, Okta, Azure AD, Auth0, etc.
//
// Lifecycle:
//
//	1. Admin opens Settings → SAML, supplies IdP metadata XML (paste or URL).
//	2. On first save, the SP self-generates an X.509 keypair, persisted in
//	   the vault. The public cert appears in the SP metadata exposed at
//	   /api/auth/saml/metadata for the IdP to trust.
//	3. End users hit /api/auth/saml/login, get redirected to the IdP, sign in,
//	   come back to /api/auth/saml/acs with a signed SAMLResponse.
//	4. We map the assertion's NameID/email to a local user (creating it if
//	   absent with source='saml'), issue a JWT, and redirect to the SPA with
//	   the token in the URL.
package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// Config is the persisted SAML SP configuration.
type Config struct {
	Enabled         bool   `json:"enabled"`
	RootURL         string `json:"root_url"`         // e.g. https://pam.example.com
	IdPMetadataXML  string `json:"idp_metadata_xml"` // pasted IdP metadata
	IdPMetadataURL  string `json:"idp_metadata_url"` // optional: fetch from URL
	EntityID        string `json:"entity_id"`        // SP entity ID (default: rootURL + /api/auth/saml/metadata)
	EmailAttribute  string `json:"email_attribute"`  // SAML attribute carrying the email, default "email"
	NameAttribute   string `json:"name_attribute"`   // optional display name attribute
	GroupAttribute  string `json:"group_attribute"`  // optional attribute carrying group membership
	DefaultRole     string `json:"default_role"`     // role for users without group mapping
	SPCertSet       bool   `json:"sp_cert_set"`      // read-only: true once the keypair is in the vault
}

// DefaultConfig returns sensible Google Workspace defaults.
func DefaultConfig() Config {
	return Config{
		EmailAttribute: "email",
		NameAttribute:  "displayName",
		GroupAttribute: "groups",
		DefaultRole:    "user",
	}
}

// Provider wraps a crewjam SAML SP. Construct via NewProvider, then call the
// HTTP handlers from your router.
type Provider struct {
	SP  *samlsp.Middleware
	Cfg Config
}

// NewProvider builds the SP middleware. Returns an error if the configuration
// is incomplete (e.g. missing IdP metadata or SP keypair).
func NewProvider(cfg Config, spCertPEM, spKeyPEM []byte) (*Provider, error) {
	if !cfg.Enabled {
		return nil, errors.New("saml: disabled")
	}
	if cfg.RootURL == "" {
		return nil, errors.New("saml: root_url required")
	}
	if cfg.IdPMetadataXML == "" {
		return nil, errors.New("saml: idp metadata XML required")
	}
	if len(spCertPEM) == 0 || len(spKeyPEM) == 0 {
		return nil, errors.New("saml: SP keypair missing — save settings to generate")
	}

	keyBlock, _ := pem.Decode(spKeyPEM)
	if keyBlock == nil {
		return nil, errors.New("saml: parse SP key PEM")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8.
		pk, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("saml: parse SP key: %w", err)
		}
		var ok bool
		privKey, ok = pk.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("saml: SP key must be RSA")
		}
	}

	certBlock, _ := pem.Decode(spCertPEM)
	if certBlock == nil {
		return nil, errors.New("saml: parse SP cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("saml: parse SP cert: %w", err)
	}

	idpMeta, err := samlsp.ParseMetadata([]byte(cfg.IdPMetadataXML))
	if err != nil {
		return nil, fmt.Errorf("saml: parse IdP metadata: %w", err)
	}

	root, err := url.Parse(cfg.RootURL)
	if err != nil {
		return nil, fmt.Errorf("saml: parse root URL: %w", err)
	}

	sp, err := samlsp.New(samlsp.Options{
		EntityID:    cfg.EntityID,
		URL:         *root,
		Key:         privKey,
		Certificate: cert,
		IDPMetadata: idpMeta,
		SignRequest: false, // many IdPs (Google) don't require signed requests
	})
	if err != nil {
		return nil, fmt.Errorf("saml: build SP: %w", err)
	}

	// Customize ACS and metadata paths to live under the gateway prefix.
	sp.ServiceProvider.AcsURL = mustURL(cfg.RootURL + "/api/auth/saml/acs")
	sp.ServiceProvider.MetadataURL = mustURL(cfg.RootURL + "/api/auth/saml/metadata")
	if cfg.EntityID == "" {
		sp.ServiceProvider.EntityID = sp.ServiceProvider.MetadataURL.String()
	}

	return &Provider{SP: sp, Cfg: cfg}, nil
}

func mustURL(s string) url.URL {
	u, _ := url.Parse(s)
	return *u
}

// AssertionClaims is what the auth-service consumes after a successful ACS.
type AssertionClaims struct {
	NameID      string
	Email       string
	DisplayName string
	Groups      []string
}

// ParseACS validates the SAMLResponse posted by the IdP and extracts attributes.
func (p *Provider) ParseACS(r *http.Request) (*AssertionClaims, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("saml: parse form: %w", err)
	}
	rawResp := r.PostForm.Get("SAMLResponse")
	if rawResp == "" {
		return nil, errors.New("saml: missing SAMLResponse")
	}

	// The crewjam library wants a TrackedRequest. For our flow we don't track
	// AuthnRequest IDs server-side (we let the IdP authenticate then come back).
	// We use ParseResponse with empty possibleRequestIDs to accept IdP-initiated
	// SSO too, which Google's "App is enabled" panels often do.
	assertion, err := p.SP.ServiceProvider.ParseResponse(r, []string{""})
	if err != nil {
		return nil, fmt.Errorf("saml: validate response: %w", err)
	}
	out := &AssertionClaims{}
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		out.NameID = assertion.Subject.NameID.Value
	}
	emailAttr := p.Cfg.EmailAttribute
	if emailAttr == "" {
		emailAttr = "email"
	}
	for _, st := range assertion.AttributeStatements {
		for _, a := range st.Attributes {
			vals := attrValues(a)
			switch {
			case isEmailAttribute(a.Name, a.FriendlyName, emailAttr):
				if len(vals) > 0 {
					out.Email = vals[0]
				}
			case p.Cfg.NameAttribute != "" && (a.Name == p.Cfg.NameAttribute || a.FriendlyName == p.Cfg.NameAttribute):
				if len(vals) > 0 {
					out.DisplayName = vals[0]
				}
			case p.Cfg.GroupAttribute != "" && (a.Name == p.Cfg.GroupAttribute || a.FriendlyName == p.Cfg.GroupAttribute):
				out.Groups = append(out.Groups, vals...)
			}
		}
	}
	// Fall back to NameID as the email if not provided as an attribute.
	if out.Email == "" {
		out.Email = out.NameID
	}
	return out, nil
}

func isEmailAttribute(name, friendly, configured string) bool {
	if configured == "" {
		configured = "email"
	}
	return name == configured ||
		friendly == configured ||
		name == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
		friendly == "email" ||
		name == "urn:oid:0.9.2342.19200300.100.1.3"
}

func attrValues(a saml.Attribute) []string {
	out := make([]string, 0, len(a.Values))
	for _, v := range a.Values {
		if v.Value != "" {
			out = append(out, v.Value)
		}
	}
	return out
}

// MakeAuthnRequestURL returns the IdP URL to redirect the user to for login.
func (p *Provider) MakeAuthnRequestURL(relayState string) (string, error) {
	req, err := p.SP.ServiceProvider.MakeAuthenticationRequest(
		p.SP.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return "", fmt.Errorf("saml: make authn request: %w", err)
	}
	redirectURL, err := req.Redirect(relayState, &p.SP.ServiceProvider)
	if err != nil {
		return "", fmt.Errorf("saml: build redirect: %w", err)
	}
	return redirectURL.String(), nil
}

// Metadata returns the SP metadata XML to give the IdP admin.
func (p *Provider) Metadata() ([]byte, error) {
	md := p.SP.ServiceProvider.Metadata()
	// Use the crewjam-provided marshaller; simpler than rolling our own.
	xmlBytes, err := samlMetadataXML(md)
	if err != nil {
		return nil, err
	}
	return xmlBytes, nil
}

// _ pin the time package — used implicitly in crewjam SAML validation; keeps
// the import list stable across refactors.
var _ = time.Now

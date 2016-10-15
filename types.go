package main

import "crypto/x509"

type Account struct {
	Email              string
	Registration       *RegistrationResource
	PrivateKey         []byte
	DomainsCertificate DomainsCertificates
	ChallengeCerts     map[string]*ChallengeCert
}

type DomainsCertificates struct {
	Certs []*DomainsCertificate
}

type DomainsCertificate struct {
	Domains     Domain
	Certificate *Certificate
}

type Domain struct {
	Main string
	SANs []string
}

type Certificate struct {
	Domain        string
	CertURL       string
	CertStableURL string
	PrivateKey    []byte
	Certificate   []byte
}

type ChallengeCert struct {
	Certificate []byte
	PrivateKey  []byte
}

type RegistrationResource struct {
	Body        Registration `json:"body,omitempty"`
	URI         string       `json:"uri,omitempty"`
	NewAuthzURL string       `json:"new_authzr_uri,omitempty"`
	TosURL      string       `json:"terms_of_service,omitempty"`
}

type Registration struct {
	Resource       string     `json:"resource,omitempty"`
	ID             int        `json:"id"`
	Key            JsonWebKey `json:"key"`
	Contact        []string   `json:"contact"`
	Agreement      string     `json:"agreement,omitempty"`
	Authorizations string     `json:"authorizations,omitempty"`
	Certificates   string     `json:"certificates,omitempty"`
}

type JsonWebKey struct {
	Key          interface{}
	Certificates []*x509.Certificate
	KeyID        string
	Algorithm    string
	Use          string
}

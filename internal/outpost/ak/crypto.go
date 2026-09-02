package ak

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"

	log "github.com/sirupsen/logrus"
	api "goauthentik.io/packages/client-go"
)

type CryptoStore struct {
	api *api.CryptoAPIService

	log *log.Entry

	fingerprints map[string]string
	certificates map[string]*tls.Certificate
}

func NewCryptoStore(cryptoApi *api.CryptoAPIService) *CryptoStore {
	return &CryptoStore{
		api:          cryptoApi,
		log:          log.WithField("logger", "authentik.outpost.cryptostore"),
		fingerprints: make(map[string]string),
		certificates: make(map[string]*tls.Certificate),
	}
}

func (cs *CryptoStore) AddKeypair(uuid string) error {
	// Check if the cached fingerprint matches the certificate,
	// if not, we re-fetch it
	if sfp, ok := cs.fingerprints[uuid]; ok {
		fp := cs.getFingerprint(uuid)
		if sfp == fp {
			return nil
		}
	}
	// reset fingerprint to force update
	cs.fingerprints[uuid] = ""
	err := cs.Fetch(uuid)
	if err != nil {
		return err
	}
	return nil
}

func (cs *CryptoStore) getFingerprint(uuid string) string {
	kp, _, err := cs.api.CryptoCertificatekeypairsRetrieve(context.Background(), uuid).Execute()
	if err != nil {
		cs.log.WithField("uuid", uuid).WithError(err).Warning("Failed to fetch certificate's fingerprint")
		return ""
	}
	return kp.GetFingerprintSha256()
}

func (cs *CryptoStore) Fetch(uuid string) error {
	cfp := cs.getFingerprint(uuid)
	if cfp == cs.fingerprints[uuid] {
		cs.log.WithField("uuid", uuid).Debug("Fingerprint hasn't changed, not fetching cert")
		return nil
	}
	cs.log.WithField("uuid", uuid).Info("Fetching certificate and private key")

	cert, _, err := cs.api.CryptoCertificatekeypairsViewCertificateRetrieve(context.Background(), uuid).Execute()
	if err != nil {
		return err
	}
	key, _, err := cs.api.CryptoCertificatekeypairsViewPrivateKeyRetrieve(context.Background(), uuid).Execute()
	if err != nil {
		return err
	}

	var tcert tls.Certificate
	if key.Data != "" {
		x509cert, err := tls.X509KeyPair([]byte(cert.Data), []byte(key.Data))
		if err != nil {
			return err
		}
		tcert = x509cert
	} else {
		var err error
		tcert, err = parseCertificate(cert.Data)
		if err != nil {
			return err
		}
	}
	cs.certificates[uuid] = &tcert
	cs.fingerprints[uuid] = cfp
	return nil
}

func (cs *CryptoStore) FetchCertificateOnly(uuid string) error {
	cs.log.WithField("uuid", uuid).Info("Fetching certificate")
	cert, _, err := cs.api.CryptoCertificatekeypairsViewCertificateRetrieve(context.Background(), uuid).Execute()
	if err != nil {
		return err
	}
	tcert, err := parseCertificate(cert.Data)
	if err != nil {
		return err
	}
	cs.certificates[uuid] = &tcert
	cs.fingerprints[uuid] = ""
	return nil
}

func parseCertificate(data string) (tls.Certificate, error) {
	var tcert tls.Certificate
	certificateData := []byte(data)
	for {
		p, rest := pem.Decode(certificateData)
		if p == nil {
			break
		}
		certificateData = rest
		if p.Type != "CERTIFICATE" {
			continue
		}
		x509cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return tls.Certificate{}, err
		}
		if tcert.Leaf == nil {
			tcert.Leaf = x509cert
		}
		tcert.Certificate = append(tcert.Certificate, x509cert.Raw)
	}
	if len(tcert.Certificate) == 0 {
		return tls.Certificate{}, errors.New("certificate data contains no certificates")
	}
	return tcert, nil
}

func (cs *CryptoStore) Get(uuid string) *tls.Certificate {
	c, ok := cs.certificates[uuid]
	if ok {
		return c
	}
	err := cs.Fetch(uuid)
	if err != nil {
		cs.log.WithError(err).Warning("failed to fetch certificate")
	}
	return cs.certificates[uuid]
}

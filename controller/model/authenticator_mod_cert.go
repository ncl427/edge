/*
	Copyright NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package model

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge/controller/apierror"
	"github.com/openziti/edge/controller/persistence"
	"github.com/openziti/edge/internal/cert"
	"github.com/openziti/foundation/util/errorz"
	nfpem "github.com/openziti/foundation/util/pem"
	cmap "github.com/orcaman/concurrent-map"
	"net/http"
	"time"
)

const (
	ClientCertHeader       = "X-Client-CertPem"
	EdgeRouterProxyRequest = "X-Edge-Router-Proxy-Request"
)

type AuthModuleCert struct {
	env                  Env
	method               string
	fingerprintGenerator cert.FingerprintGenerator
	caChain              []byte
	staticCaCerts        []*x509.Certificate
	dynamicCaCache       cmap.ConcurrentMap //map[string][]*x509.Certificate
}

func NewAuthModuleCert(env Env, caChain []byte) *AuthModuleCert {
	handler := &AuthModuleCert{
		env:                  env,
		method:               persistence.MethodAuthenticatorCert,
		fingerprintGenerator: cert.NewFingerprintGenerator(),
		staticCaCerts:        nfpem.PemToX509(string(caChain)),
		dynamicCaCache:       cmap.New(),
	}

	return handler
}

func (module *AuthModuleCert) CanHandle(method string) bool {
	return method == module.method
}

func (module *AuthModuleCert) Process(context AuthContext) (string, error) {
	fingerprints, err := module.GetFingerprints(context)

	if err != nil {
		return "", err
	}

	for fingerprint, cert := range fingerprints {
		authenticator, err := module.env.GetHandlers().Authenticator.ReadByFingerprint(fingerprint)

		if err != nil {
			pfxlog.Logger().WithError(err).Errorf("error during cert auth read by fingerprint %s", fingerprint)
		}

		if authenticator != nil {
			curCert := fingerprints[fingerprint]
			if authCert, ok := authenticator.SubType.(*AuthenticatorCert); ok {
				if authCert.Pem == "" {
					certPem := pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: curCert.Raw,
					})

					authCert.Pem = string(certPem)
					if err = module.env.GetHandlers().Authenticator.Update(authenticator); err != nil {
						pfxlog.Logger().WithError(err).Errorf("error during cert auth attempting to update PEM, fingerprint: %s", fingerprint)
					}
				}
			}

			//ignore client cert expiration windows
			cert.NotBefore = time.Now().Add(-1 * time.Hour)
			cert.NotAfter = time.Now().Add(1 * time.Hour)

			opts := x509.VerifyOptions{
				Roots:         module.getRootPool(),
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}

			if _, err := cert.Verify(opts); err == nil {
				return authenticator.IdentityId, nil
			} else {
				pfxlog.Logger().Tracef("error verifying client certificate [%s] did not verify: %v", fingerprint, err)
			}
		}
	}

	return "", apierror.NewInvalidAuth()
}

func (module *AuthModuleCert) getRootPool() *x509.CertPool {
	roots := x509.NewCertPool()

	for _, caCert := range module.staticCaCerts {
		roots.AddCert(caCert)
	}

	err := module.env.GetHandlers().Ca.Stream("isAuthEnabled = true and isVerified = true", func(ca *Ca, err error) error {
		if ca == nil && err == nil {
			return nil
		}

		if err != nil {
			//continue on err
			pfxlog.Logger().Errorf("error streaming cas for authentication: %vs", err)
			return nil
		}

		if val, ok := module.dynamicCaCache.Get(ca.Id); ok {
			if caCerts, ok := val.([]*x509.Certificate); ok {
				for _, caCert := range caCerts {
					roots.AddCert(caCert)
				}
			}
		} else {
			caCerts := nfpem.PemToX509(ca.CertPem)
			module.dynamicCaCache.Set(ca.Id, caCerts)
			for _, caCert := range caCerts {
				roots.AddCert(caCert)
			}
		}

		return nil
	})

	if err != nil {
		return nil
	}

	return roots
}

func (module *AuthModuleCert) isEdgeRouter(certs []*x509.Certificate) bool {

	for _, certificate := range certs {
		fingerprint := module.fingerprintGenerator.FromCert(certificate)

		router, err := module.env.GetHandlers().EdgeRouter.ReadOneByFingerprint(fingerprint)

		if router != nil {
			return true
		}

		if err != nil {
			pfxlog.Logger().WithError(err).Errorf("could not read edge router by fingerprint %s", fingerprint)
		}
	}
	return false
}

func (module *AuthModuleCert) GetFingerprints(ctx AuthContext) (cert.Fingerprints, error) {
	peerCerts := ctx.GetCerts()
	authCerts := peerCerts
	proxiedRaw64 := ""

	if proxiedRaw64Interface := ctx.GetHeaders()[ClientCertHeader]; proxiedRaw64Interface != nil {
		proxiedRaw64 = proxiedRaw64Interface.(string)
	}

	isProxied := false

	if proxyHeader := ctx.GetHeaders()[EdgeRouterProxyRequest]; proxyHeader != nil {
		isProxied = true
	}

	if isProxied && proxiedRaw64 == "" {
		return nil, apierror.NewInvalidAuth()
	}

	if proxiedRaw64 != "" {

		isValid := module.isEdgeRouter(ctx.GetCerts())

		if !isValid {
			return nil, apierror.NewInvalidAuth()
		}

		var proxiedRaw []byte
		_, err := base64.StdEncoding.Decode(proxiedRaw, []byte(proxiedRaw64))

		if err != nil {
			return nil, &errorz.ApiError{
				Code:    apierror.CouldNotDecodeProxiedCertCode,
				Message: apierror.CouldNotDecodeProxiedCertMessage,
				Cause:   err,
				Status:  http.StatusBadRequest,
			}
		}

		proxiedCerts, err := x509.ParseCertificates(proxiedRaw)

		if err != nil {
			return nil, &errorz.ApiError{
				Code:    apierror.CouldNotParseX509FromDerCode,
				Message: apierror.CouldNotParseX509FromDerMessage,
				Cause:   err,
				Status:  http.StatusBadRequest,
			}
		}

		authCerts = proxiedCerts
	}

	return module.fingerprintGenerator.FromCerts(authCerts), nil
}

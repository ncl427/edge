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
	"encoding/json"
	"net/http"
)

type AuthResult interface {
	IdentityId() string
	ExternalId() string
	AuthenticatorId() string
	SessionCerts() []*x509.Certificate
	Identity() *Identity
	Authenticator() *Authenticator
	AuthPolicy() *AuthPolicy
	AuthPolicyId() string
	IsSuccessful() bool
}

type AuthProcessor interface {
	CanHandle(method string) bool
	Process(context AuthContext) (AuthResult, error)
}

type AuthRegistry interface {
	Add(method AuthProcessor)
	GetByMethod(method string) AuthProcessor
}

type AuthProcessorRegistryImpl struct {
	processors []AuthProcessor
}

func (registry *AuthProcessorRegistryImpl) Add(processor AuthProcessor) {
	registry.processors = append(registry.processors, processor)
}

func (registry *AuthProcessorRegistryImpl) GetByMethod(method string) AuthProcessor {
	for _, processor := range registry.processors {
		if processor.CanHandle(method) {
			return processor
		}
	}
	return nil
}

type AuthContext interface {
	GetMethod() string
	GetData() map[string]interface{}
	GetCerts() []*x509.Certificate
	GetHeaders() map[string]interface{}
}

type AuthContextHttp struct {
	Method  string
	Data    map[string]interface{}
	Certs   []*x509.Certificate
	Headers map[string]interface{}
}

func NewAuthContextHttp(request *http.Request, method string, data interface{}) AuthContext {
	//TODO: this is a giant hack to not deal w/ removing the AuthContext layer
	sigh, _ := json.Marshal(data)
	mapData := map[string]interface{}{}
	_ = json.Unmarshal(sigh, &mapData)

	headers := map[string]interface{}{}
	for h, v := range request.Header {
		headers[h] = v
	}

	return &AuthContextHttp{
		Method:  method,
		Data:    mapData,
		Certs:   request.TLS.PeerCertificates,
		Headers: headers,
	}
}

func (context *AuthContextHttp) GetMethod() string {
	return context.Method
}

func (context *AuthContextHttp) GetData() map[string]interface{} {
	return context.Data
}

func (context *AuthContextHttp) GetHeaders() map[string]interface{} {
	return context.Headers
}

func (context *AuthContextHttp) GetCerts() []*x509.Certificate {
	return context.Certs
}

var _ AuthResult = &AuthResultBase{}

type AuthResultBase struct {
	identityId      string
	externalId      string
	identity        *Identity
	authenticatorId string
	authenticator   *Authenticator
	sessionCerts    []*x509.Certificate
	authPolicyId    string
	authPolicy      *AuthPolicy
	env             Env
}

func (a *AuthResultBase) IdentityId() string {
	return a.identityId
}

func (a *AuthResultBase) ExternalId() string {
	return a.externalId
}

func (a *AuthResultBase) AuthenticatorId() string {
	return a.authenticatorId
}

func (a *AuthResultBase) SessionCerts() []*x509.Certificate {
	return a.sessionCerts
}

func (a *AuthResultBase) Identity() *Identity {
	if a.identity == nil {
		if a.identityId != "" {
			a.identity, _ = a.env.GetManagers().Identity.Read(a.identityId)
		} else if a.externalId != "" {
			a.identity, _ = a.env.GetManagers().Identity.ReadByExternalId(a.externalId)
		}

	}
	return a.identity
}

func (a *AuthResultBase) Authenticator() *Authenticator {
	if a.authenticator == nil {
		a.authenticator, _ = a.env.GetManagers().Authenticator.Read(a.authenticatorId)
	}
	return a.authenticator
}

func (a *AuthResultBase) AuthPolicy() *AuthPolicy {
	if a.authPolicy == nil {
		a.authPolicy, _ = a.env.GetManagers().AuthPolicy.Read(a.authPolicyId)
	}

	return a.authPolicy
}

func (a *AuthResultBase) AuthPolicyId() string {
	return a.authPolicyId
}

func (a *AuthResultBase) IsSuccessful() bool {
	return a.identityId != ""
}

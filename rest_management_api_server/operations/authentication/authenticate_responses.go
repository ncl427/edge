// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// __          __              _
// \ \        / /             (_)
//  \ \  /\  / /_ _ _ __ _ __  _ _ __   __ _
//   \ \/  \/ / _` | '__| '_ \| | '_ \ / _` |
//    \  /\  / (_| | |  | | | | | | | | (_| | : This file is generated, do not edit it.
//     \/  \/ \__,_|_|  |_| |_|_|_| |_|\__, |
//                                      __/ |
//                                     |___/

package authentication

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// AuthenticateOKCode is the HTTP code returned for type AuthenticateOK
const AuthenticateOKCode int = 200

/*AuthenticateOK The API session associated with the session used to issue the request

swagger:response authenticateOK
*/
type AuthenticateOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.CurrentAPISessionDetailEnvelope `json:"body,omitempty"`
}

// NewAuthenticateOK creates AuthenticateOK with default headers values
func NewAuthenticateOK() *AuthenticateOK {

	return &AuthenticateOK{}
}

// WithPayload adds the payload to the authenticate o k response
func (o *AuthenticateOK) WithPayload(payload *rest_model.CurrentAPISessionDetailEnvelope) *AuthenticateOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the authenticate o k response
func (o *AuthenticateOK) SetPayload(payload *rest_model.CurrentAPISessionDetailEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *AuthenticateOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// AuthenticateBadRequestCode is the HTTP code returned for type AuthenticateBadRequest
const AuthenticateBadRequestCode int = 400

/*AuthenticateBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response authenticateBadRequest
*/
type AuthenticateBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewAuthenticateBadRequest creates AuthenticateBadRequest with default headers values
func NewAuthenticateBadRequest() *AuthenticateBadRequest {

	return &AuthenticateBadRequest{}
}

// WithPayload adds the payload to the authenticate bad request response
func (o *AuthenticateBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *AuthenticateBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the authenticate bad request response
func (o *AuthenticateBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *AuthenticateBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// AuthenticateForbiddenCode is the HTTP code returned for type AuthenticateForbidden
const AuthenticateForbiddenCode int = 403

/*AuthenticateForbidden The authentication request could not be processed as the credentials are invalid

swagger:response authenticateForbidden
*/
type AuthenticateForbidden struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewAuthenticateForbidden creates AuthenticateForbidden with default headers values
func NewAuthenticateForbidden() *AuthenticateForbidden {

	return &AuthenticateForbidden{}
}

// WithPayload adds the payload to the authenticate forbidden response
func (o *AuthenticateForbidden) WithPayload(payload *rest_model.APIErrorEnvelope) *AuthenticateForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the authenticate forbidden response
func (o *AuthenticateForbidden) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *AuthenticateForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

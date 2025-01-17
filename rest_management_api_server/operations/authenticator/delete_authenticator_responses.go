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

package authenticator

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// DeleteAuthenticatorOKCode is the HTTP code returned for type DeleteAuthenticatorOK
const DeleteAuthenticatorOKCode int = 200

/*DeleteAuthenticatorOK The delete request was successful and the resource has been removed

swagger:response deleteAuthenticatorOK
*/
type DeleteAuthenticatorOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewDeleteAuthenticatorOK creates DeleteAuthenticatorOK with default headers values
func NewDeleteAuthenticatorOK() *DeleteAuthenticatorOK {

	return &DeleteAuthenticatorOK{}
}

// WithPayload adds the payload to the delete authenticator o k response
func (o *DeleteAuthenticatorOK) WithPayload(payload *rest_model.Empty) *DeleteAuthenticatorOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete authenticator o k response
func (o *DeleteAuthenticatorOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteAuthenticatorOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteAuthenticatorBadRequestCode is the HTTP code returned for type DeleteAuthenticatorBadRequest
const DeleteAuthenticatorBadRequestCode int = 400

/*DeleteAuthenticatorBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response deleteAuthenticatorBadRequest
*/
type DeleteAuthenticatorBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDeleteAuthenticatorBadRequest creates DeleteAuthenticatorBadRequest with default headers values
func NewDeleteAuthenticatorBadRequest() *DeleteAuthenticatorBadRequest {

	return &DeleteAuthenticatorBadRequest{}
}

// WithPayload adds the payload to the delete authenticator bad request response
func (o *DeleteAuthenticatorBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *DeleteAuthenticatorBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete authenticator bad request response
func (o *DeleteAuthenticatorBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteAuthenticatorBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteAuthenticatorUnauthorizedCode is the HTTP code returned for type DeleteAuthenticatorUnauthorized
const DeleteAuthenticatorUnauthorizedCode int = 401

/*DeleteAuthenticatorUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response deleteAuthenticatorUnauthorized
*/
type DeleteAuthenticatorUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDeleteAuthenticatorUnauthorized creates DeleteAuthenticatorUnauthorized with default headers values
func NewDeleteAuthenticatorUnauthorized() *DeleteAuthenticatorUnauthorized {

	return &DeleteAuthenticatorUnauthorized{}
}

// WithPayload adds the payload to the delete authenticator unauthorized response
func (o *DeleteAuthenticatorUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *DeleteAuthenticatorUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete authenticator unauthorized response
func (o *DeleteAuthenticatorUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteAuthenticatorUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

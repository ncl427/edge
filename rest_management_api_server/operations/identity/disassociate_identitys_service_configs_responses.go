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

package identity

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// DisassociateIdentitysServiceConfigsOKCode is the HTTP code returned for type DisassociateIdentitysServiceConfigsOK
const DisassociateIdentitysServiceConfigsOKCode int = 200

/*DisassociateIdentitysServiceConfigsOK Base empty response

swagger:response disassociateIdentitysServiceConfigsOK
*/
type DisassociateIdentitysServiceConfigsOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewDisassociateIdentitysServiceConfigsOK creates DisassociateIdentitysServiceConfigsOK with default headers values
func NewDisassociateIdentitysServiceConfigsOK() *DisassociateIdentitysServiceConfigsOK {

	return &DisassociateIdentitysServiceConfigsOK{}
}

// WithPayload adds the payload to the disassociate identitys service configs o k response
func (o *DisassociateIdentitysServiceConfigsOK) WithPayload(payload *rest_model.Empty) *DisassociateIdentitysServiceConfigsOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the disassociate identitys service configs o k response
func (o *DisassociateIdentitysServiceConfigsOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DisassociateIdentitysServiceConfigsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DisassociateIdentitysServiceConfigsBadRequestCode is the HTTP code returned for type DisassociateIdentitysServiceConfigsBadRequest
const DisassociateIdentitysServiceConfigsBadRequestCode int = 400

/*DisassociateIdentitysServiceConfigsBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response disassociateIdentitysServiceConfigsBadRequest
*/
type DisassociateIdentitysServiceConfigsBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDisassociateIdentitysServiceConfigsBadRequest creates DisassociateIdentitysServiceConfigsBadRequest with default headers values
func NewDisassociateIdentitysServiceConfigsBadRequest() *DisassociateIdentitysServiceConfigsBadRequest {

	return &DisassociateIdentitysServiceConfigsBadRequest{}
}

// WithPayload adds the payload to the disassociate identitys service configs bad request response
func (o *DisassociateIdentitysServiceConfigsBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *DisassociateIdentitysServiceConfigsBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the disassociate identitys service configs bad request response
func (o *DisassociateIdentitysServiceConfigsBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DisassociateIdentitysServiceConfigsBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DisassociateIdentitysServiceConfigsUnauthorizedCode is the HTTP code returned for type DisassociateIdentitysServiceConfigsUnauthorized
const DisassociateIdentitysServiceConfigsUnauthorizedCode int = 401

/*DisassociateIdentitysServiceConfigsUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response disassociateIdentitysServiceConfigsUnauthorized
*/
type DisassociateIdentitysServiceConfigsUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDisassociateIdentitysServiceConfigsUnauthorized creates DisassociateIdentitysServiceConfigsUnauthorized with default headers values
func NewDisassociateIdentitysServiceConfigsUnauthorized() *DisassociateIdentitysServiceConfigsUnauthorized {

	return &DisassociateIdentitysServiceConfigsUnauthorized{}
}

// WithPayload adds the payload to the disassociate identitys service configs unauthorized response
func (o *DisassociateIdentitysServiceConfigsUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *DisassociateIdentitysServiceConfigsUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the disassociate identitys service configs unauthorized response
func (o *DisassociateIdentitysServiceConfigsUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DisassociateIdentitysServiceConfigsUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DisassociateIdentitysServiceConfigsNotFoundCode is the HTTP code returned for type DisassociateIdentitysServiceConfigsNotFound
const DisassociateIdentitysServiceConfigsNotFoundCode int = 404

/*DisassociateIdentitysServiceConfigsNotFound The requested resource does not exist

swagger:response disassociateIdentitysServiceConfigsNotFound
*/
type DisassociateIdentitysServiceConfigsNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDisassociateIdentitysServiceConfigsNotFound creates DisassociateIdentitysServiceConfigsNotFound with default headers values
func NewDisassociateIdentitysServiceConfigsNotFound() *DisassociateIdentitysServiceConfigsNotFound {

	return &DisassociateIdentitysServiceConfigsNotFound{}
}

// WithPayload adds the payload to the disassociate identitys service configs not found response
func (o *DisassociateIdentitysServiceConfigsNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *DisassociateIdentitysServiceConfigsNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the disassociate identitys service configs not found response
func (o *DisassociateIdentitysServiceConfigsNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DisassociateIdentitysServiceConfigsNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

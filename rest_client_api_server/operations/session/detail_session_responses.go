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

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// DetailSessionOKCode is the HTTP code returned for type DetailSessionOK
const DetailSessionOKCode int = 200

/*DetailSessionOK A single session

swagger:response detailSessionOK
*/
type DetailSessionOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.DetailSessionEnvelope `json:"body,omitempty"`
}

// NewDetailSessionOK creates DetailSessionOK with default headers values
func NewDetailSessionOK() *DetailSessionOK {

	return &DetailSessionOK{}
}

// WithPayload adds the payload to the detail session o k response
func (o *DetailSessionOK) WithPayload(payload *rest_model.DetailSessionEnvelope) *DetailSessionOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail session o k response
func (o *DetailSessionOK) SetPayload(payload *rest_model.DetailSessionEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailSessionOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailSessionUnauthorizedCode is the HTTP code returned for type DetailSessionUnauthorized
const DetailSessionUnauthorizedCode int = 401

/*DetailSessionUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response detailSessionUnauthorized
*/
type DetailSessionUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailSessionUnauthorized creates DetailSessionUnauthorized with default headers values
func NewDetailSessionUnauthorized() *DetailSessionUnauthorized {

	return &DetailSessionUnauthorized{}
}

// WithPayload adds the payload to the detail session unauthorized response
func (o *DetailSessionUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *DetailSessionUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail session unauthorized response
func (o *DetailSessionUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailSessionUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailSessionNotFoundCode is the HTTP code returned for type DetailSessionNotFound
const DetailSessionNotFoundCode int = 404

/*DetailSessionNotFound The requested resource does not exist

swagger:response detailSessionNotFound
*/
type DetailSessionNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailSessionNotFound creates DetailSessionNotFound with default headers values
func NewDetailSessionNotFound() *DetailSessionNotFound {

	return &DetailSessionNotFound{}
}

// WithPayload adds the payload to the detail session not found response
func (o *DetailSessionNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *DetailSessionNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail session not found response
func (o *DetailSessionNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailSessionNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

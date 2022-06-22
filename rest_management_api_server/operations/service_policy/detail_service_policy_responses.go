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

package service_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// DetailServicePolicyOKCode is the HTTP code returned for type DetailServicePolicyOK
const DetailServicePolicyOKCode int = 200

/*DetailServicePolicyOK A single service policy

swagger:response detailServicePolicyOK
*/
type DetailServicePolicyOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.DetailServicePolicyEnvelop `json:"body,omitempty"`
}

// NewDetailServicePolicyOK creates DetailServicePolicyOK with default headers values
func NewDetailServicePolicyOK() *DetailServicePolicyOK {

	return &DetailServicePolicyOK{}
}

// WithPayload adds the payload to the detail service policy o k response
func (o *DetailServicePolicyOK) WithPayload(payload *rest_model.DetailServicePolicyEnvelop) *DetailServicePolicyOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail service policy o k response
func (o *DetailServicePolicyOK) SetPayload(payload *rest_model.DetailServicePolicyEnvelop) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailServicePolicyOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailServicePolicyUnauthorizedCode is the HTTP code returned for type DetailServicePolicyUnauthorized
const DetailServicePolicyUnauthorizedCode int = 401

/*DetailServicePolicyUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response detailServicePolicyUnauthorized
*/
type DetailServicePolicyUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailServicePolicyUnauthorized creates DetailServicePolicyUnauthorized with default headers values
func NewDetailServicePolicyUnauthorized() *DetailServicePolicyUnauthorized {

	return &DetailServicePolicyUnauthorized{}
}

// WithPayload adds the payload to the detail service policy unauthorized response
func (o *DetailServicePolicyUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *DetailServicePolicyUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail service policy unauthorized response
func (o *DetailServicePolicyUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailServicePolicyUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailServicePolicyNotFoundCode is the HTTP code returned for type DetailServicePolicyNotFound
const DetailServicePolicyNotFoundCode int = 404

/*DetailServicePolicyNotFound The requested resource does not exist

swagger:response detailServicePolicyNotFound
*/
type DetailServicePolicyNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailServicePolicyNotFound creates DetailServicePolicyNotFound with default headers values
func NewDetailServicePolicyNotFound() *DetailServicePolicyNotFound {

	return &DetailServicePolicyNotFound{}
}

// WithPayload adds the payload to the detail service policy not found response
func (o *DetailServicePolicyNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *DetailServicePolicyNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail service policy not found response
func (o *DetailServicePolicyNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailServicePolicyNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

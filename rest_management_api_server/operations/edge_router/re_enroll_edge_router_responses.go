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

package edge_router

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// ReEnrollEdgeRouterOKCode is the HTTP code returned for type ReEnrollEdgeRouterOK
const ReEnrollEdgeRouterOKCode int = 200

/*ReEnrollEdgeRouterOK Base empty response

swagger:response reEnrollEdgeRouterOK
*/
type ReEnrollEdgeRouterOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewReEnrollEdgeRouterOK creates ReEnrollEdgeRouterOK with default headers values
func NewReEnrollEdgeRouterOK() *ReEnrollEdgeRouterOK {

	return &ReEnrollEdgeRouterOK{}
}

// WithPayload adds the payload to the re enroll edge router o k response
func (o *ReEnrollEdgeRouterOK) WithPayload(payload *rest_model.Empty) *ReEnrollEdgeRouterOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the re enroll edge router o k response
func (o *ReEnrollEdgeRouterOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ReEnrollEdgeRouterOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ReEnrollEdgeRouterUnauthorizedCode is the HTTP code returned for type ReEnrollEdgeRouterUnauthorized
const ReEnrollEdgeRouterUnauthorizedCode int = 401

/*ReEnrollEdgeRouterUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response reEnrollEdgeRouterUnauthorized
*/
type ReEnrollEdgeRouterUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewReEnrollEdgeRouterUnauthorized creates ReEnrollEdgeRouterUnauthorized with default headers values
func NewReEnrollEdgeRouterUnauthorized() *ReEnrollEdgeRouterUnauthorized {

	return &ReEnrollEdgeRouterUnauthorized{}
}

// WithPayload adds the payload to the re enroll edge router unauthorized response
func (o *ReEnrollEdgeRouterUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *ReEnrollEdgeRouterUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the re enroll edge router unauthorized response
func (o *ReEnrollEdgeRouterUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ReEnrollEdgeRouterUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ReEnrollEdgeRouterNotFoundCode is the HTTP code returned for type ReEnrollEdgeRouterNotFound
const ReEnrollEdgeRouterNotFoundCode int = 404

/*ReEnrollEdgeRouterNotFound The requested resource does not exist

swagger:response reEnrollEdgeRouterNotFound
*/
type ReEnrollEdgeRouterNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewReEnrollEdgeRouterNotFound creates ReEnrollEdgeRouterNotFound with default headers values
func NewReEnrollEdgeRouterNotFound() *ReEnrollEdgeRouterNotFound {

	return &ReEnrollEdgeRouterNotFound{}
}

// WithPayload adds the payload to the re enroll edge router not found response
func (o *ReEnrollEdgeRouterNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *ReEnrollEdgeRouterNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the re enroll edge router not found response
func (o *ReEnrollEdgeRouterNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ReEnrollEdgeRouterNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

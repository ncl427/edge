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

package router

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// DetailTransitRouterOKCode is the HTTP code returned for type DetailTransitRouterOK
const DetailTransitRouterOKCode int = 200

/*DetailTransitRouterOK A single router

swagger:response detailTransitRouterOK
*/
type DetailTransitRouterOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.DetailRouterEnvelope `json:"body,omitempty"`
}

// NewDetailTransitRouterOK creates DetailTransitRouterOK with default headers values
func NewDetailTransitRouterOK() *DetailTransitRouterOK {

	return &DetailTransitRouterOK{}
}

// WithPayload adds the payload to the detail transit router o k response
func (o *DetailTransitRouterOK) WithPayload(payload *rest_model.DetailRouterEnvelope) *DetailTransitRouterOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail transit router o k response
func (o *DetailTransitRouterOK) SetPayload(payload *rest_model.DetailRouterEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailTransitRouterOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailTransitRouterUnauthorizedCode is the HTTP code returned for type DetailTransitRouterUnauthorized
const DetailTransitRouterUnauthorizedCode int = 401

/*DetailTransitRouterUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response detailTransitRouterUnauthorized
*/
type DetailTransitRouterUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailTransitRouterUnauthorized creates DetailTransitRouterUnauthorized with default headers values
func NewDetailTransitRouterUnauthorized() *DetailTransitRouterUnauthorized {

	return &DetailTransitRouterUnauthorized{}
}

// WithPayload adds the payload to the detail transit router unauthorized response
func (o *DetailTransitRouterUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *DetailTransitRouterUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail transit router unauthorized response
func (o *DetailTransitRouterUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailTransitRouterUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailTransitRouterNotFoundCode is the HTTP code returned for type DetailTransitRouterNotFound
const DetailTransitRouterNotFoundCode int = 404

/*DetailTransitRouterNotFound The requested resource does not exist

swagger:response detailTransitRouterNotFound
*/
type DetailTransitRouterNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailTransitRouterNotFound creates DetailTransitRouterNotFound with default headers values
func NewDetailTransitRouterNotFound() *DetailTransitRouterNotFound {

	return &DetailTransitRouterNotFound{}
}

// WithPayload adds the payload to the detail transit router not found response
func (o *DetailTransitRouterNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *DetailTransitRouterNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail transit router not found response
func (o *DetailTransitRouterNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailTransitRouterNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

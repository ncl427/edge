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

package posture_checks

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// DetailPostureCheckOKCode is the HTTP code returned for type DetailPostureCheckOK
const DetailPostureCheckOKCode int = 200

/*DetailPostureCheckOK Retrieves a singular posture check by id

swagger:response detailPostureCheckOK
*/
type DetailPostureCheckOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.DetailPostureCheckEnvelope `json:"body,omitempty"`
}

// NewDetailPostureCheckOK creates DetailPostureCheckOK with default headers values
func NewDetailPostureCheckOK() *DetailPostureCheckOK {

	return &DetailPostureCheckOK{}
}

// WithPayload adds the payload to the detail posture check o k response
func (o *DetailPostureCheckOK) WithPayload(payload *rest_model.DetailPostureCheckEnvelope) *DetailPostureCheckOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail posture check o k response
func (o *DetailPostureCheckOK) SetPayload(payload *rest_model.DetailPostureCheckEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailPostureCheckOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailPostureCheckUnauthorizedCode is the HTTP code returned for type DetailPostureCheckUnauthorized
const DetailPostureCheckUnauthorizedCode int = 401

/*DetailPostureCheckUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response detailPostureCheckUnauthorized
*/
type DetailPostureCheckUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailPostureCheckUnauthorized creates DetailPostureCheckUnauthorized with default headers values
func NewDetailPostureCheckUnauthorized() *DetailPostureCheckUnauthorized {

	return &DetailPostureCheckUnauthorized{}
}

// WithPayload adds the payload to the detail posture check unauthorized response
func (o *DetailPostureCheckUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *DetailPostureCheckUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail posture check unauthorized response
func (o *DetailPostureCheckUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailPostureCheckUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailPostureCheckNotFoundCode is the HTTP code returned for type DetailPostureCheckNotFound
const DetailPostureCheckNotFoundCode int = 404

/*DetailPostureCheckNotFound The requested resource does not exist

swagger:response detailPostureCheckNotFound
*/
type DetailPostureCheckNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailPostureCheckNotFound creates DetailPostureCheckNotFound with default headers values
func NewDetailPostureCheckNotFound() *DetailPostureCheckNotFound {

	return &DetailPostureCheckNotFound{}
}

// WithPayload adds the payload to the detail posture check not found response
func (o *DetailPostureCheckNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *DetailPostureCheckNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail posture check not found response
func (o *DetailPostureCheckNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailPostureCheckNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

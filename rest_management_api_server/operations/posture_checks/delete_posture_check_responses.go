// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry, Inc.
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

// DeletePostureCheckOKCode is the HTTP code returned for type DeletePostureCheckOK
const DeletePostureCheckOKCode int = 200

/*DeletePostureCheckOK The delete request was successful and the resource has been removed

swagger:response deletePostureCheckOK
*/
type DeletePostureCheckOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewDeletePostureCheckOK creates DeletePostureCheckOK with default headers values
func NewDeletePostureCheckOK() *DeletePostureCheckOK {

	return &DeletePostureCheckOK{}
}

// WithPayload adds the payload to the delete posture check o k response
func (o *DeletePostureCheckOK) WithPayload(payload *rest_model.Empty) *DeletePostureCheckOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete posture check o k response
func (o *DeletePostureCheckOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeletePostureCheckOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeletePostureCheckForbiddenCode is the HTTP code returned for type DeletePostureCheckForbidden
const DeletePostureCheckForbiddenCode int = 403

/*DeletePostureCheckForbidden The currently supplied session does not have the correct access rights to request this resource

swagger:response deletePostureCheckForbidden
*/
type DeletePostureCheckForbidden struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDeletePostureCheckForbidden creates DeletePostureCheckForbidden with default headers values
func NewDeletePostureCheckForbidden() *DeletePostureCheckForbidden {

	return &DeletePostureCheckForbidden{}
}

// WithPayload adds the payload to the delete posture check forbidden response
func (o *DeletePostureCheckForbidden) WithPayload(payload *rest_model.APIErrorEnvelope) *DeletePostureCheckForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete posture check forbidden response
func (o *DeletePostureCheckForbidden) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeletePostureCheckForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeletePostureCheckNotFoundCode is the HTTP code returned for type DeletePostureCheckNotFound
const DeletePostureCheckNotFoundCode int = 404

/*DeletePostureCheckNotFound The requested resource does not exist

swagger:response deletePostureCheckNotFound
*/
type DeletePostureCheckNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDeletePostureCheckNotFound creates DeletePostureCheckNotFound with default headers values
func NewDeletePostureCheckNotFound() *DeletePostureCheckNotFound {

	return &DeletePostureCheckNotFound{}
}

// WithPayload adds the payload to the delete posture check not found response
func (o *DeletePostureCheckNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *DeletePostureCheckNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete posture check not found response
func (o *DeletePostureCheckNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeletePostureCheckNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
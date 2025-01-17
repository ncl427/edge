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

package certificate_authority

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// DetailCaReader is a Reader for the DetailCa structure.
type DetailCaReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DetailCaReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDetailCaOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDetailCaUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDetailCaNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDetailCaOK creates a DetailCaOK with default headers values
func NewDetailCaOK() *DetailCaOK {
	return &DetailCaOK{}
}

/* DetailCaOK describes a response with status code 200, with default header values.

A singular Certificate Authority (CA) resource
*/
type DetailCaOK struct {
	Payload *rest_model.DetailCaEnvelope
}

func (o *DetailCaOK) Error() string {
	return fmt.Sprintf("[GET /cas/{id}][%d] detailCaOK  %+v", 200, o.Payload)
}
func (o *DetailCaOK) GetPayload() *rest_model.DetailCaEnvelope {
	return o.Payload
}

func (o *DetailCaOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.DetailCaEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailCaUnauthorized creates a DetailCaUnauthorized with default headers values
func NewDetailCaUnauthorized() *DetailCaUnauthorized {
	return &DetailCaUnauthorized{}
}

/* DetailCaUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type DetailCaUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailCaUnauthorized) Error() string {
	return fmt.Sprintf("[GET /cas/{id}][%d] detailCaUnauthorized  %+v", 401, o.Payload)
}
func (o *DetailCaUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailCaUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailCaNotFound creates a DetailCaNotFound with default headers values
func NewDetailCaNotFound() *DetailCaNotFound {
	return &DetailCaNotFound{}
}

/* DetailCaNotFound describes a response with status code 404, with default header values.

The requested resource does not exist
*/
type DetailCaNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailCaNotFound) Error() string {
	return fmt.Sprintf("[GET /cas/{id}][%d] detailCaNotFound  %+v", 404, o.Payload)
}
func (o *DetailCaNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailCaNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

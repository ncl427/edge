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

package enroll

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// EnrollOttReader is a Reader for the EnrollOtt structure.
type EnrollOttReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *EnrollOttReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewEnrollOttOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 404:
		result := NewEnrollOttNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewEnrollOttOK creates a EnrollOttOK with default headers values
func NewEnrollOttOK() *EnrollOttOK {
	return &EnrollOttOK{}
}

/* EnrollOttOK describes a response with status code 200, with default header values.

A PEM encoded certificate signed by the internal Ziti CA
*/
type EnrollOttOK struct {
	Payload string
}

func (o *EnrollOttOK) Error() string {
	return fmt.Sprintf("[POST /enroll/ott][%d] enrollOttOK  %+v", 200, o.Payload)
}
func (o *EnrollOttOK) GetPayload() string {
	return o.Payload
}

func (o *EnrollOttOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEnrollOttNotFound creates a EnrollOttNotFound with default headers values
func NewEnrollOttNotFound() *EnrollOttNotFound {
	return &EnrollOttNotFound{}
}

/* EnrollOttNotFound describes a response with status code 404, with default header values.

The requested resource does not exist
*/
type EnrollOttNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *EnrollOttNotFound) Error() string {
	return fmt.Sprintf("[POST /enroll/ott][%d] enrollOttNotFound  %+v", 404, o.Payload)
}
func (o *EnrollOttNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *EnrollOttNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

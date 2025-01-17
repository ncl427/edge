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

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// ListConfigTypesReader is a Reader for the ListConfigTypes structure.
type ListConfigTypesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListConfigTypesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListConfigTypesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListConfigTypesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListConfigTypesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListConfigTypesOK creates a ListConfigTypesOK with default headers values
func NewListConfigTypesOK() *ListConfigTypesOK {
	return &ListConfigTypesOK{}
}

/* ListConfigTypesOK describes a response with status code 200, with default header values.

A list of config-types
*/
type ListConfigTypesOK struct {
	Payload *rest_model.ListConfigTypesEnvelope
}

func (o *ListConfigTypesOK) Error() string {
	return fmt.Sprintf("[GET /config-types][%d] listConfigTypesOK  %+v", 200, o.Payload)
}
func (o *ListConfigTypesOK) GetPayload() *rest_model.ListConfigTypesEnvelope {
	return o.Payload
}

func (o *ListConfigTypesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.ListConfigTypesEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListConfigTypesBadRequest creates a ListConfigTypesBadRequest with default headers values
func NewListConfigTypesBadRequest() *ListConfigTypesBadRequest {
	return &ListConfigTypesBadRequest{}
}

/* ListConfigTypesBadRequest describes a response with status code 400, with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type ListConfigTypesBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListConfigTypesBadRequest) Error() string {
	return fmt.Sprintf("[GET /config-types][%d] listConfigTypesBadRequest  %+v", 400, o.Payload)
}
func (o *ListConfigTypesBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListConfigTypesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListConfigTypesUnauthorized creates a ListConfigTypesUnauthorized with default headers values
func NewListConfigTypesUnauthorized() *ListConfigTypesUnauthorized {
	return &ListConfigTypesUnauthorized{}
}

/* ListConfigTypesUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type ListConfigTypesUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListConfigTypesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /config-types][%d] listConfigTypesUnauthorized  %+v", 401, o.Payload)
}
func (o *ListConfigTypesUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListConfigTypesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

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

// ListConfigsReader is a Reader for the ListConfigs structure.
type ListConfigsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListConfigsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListConfigsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListConfigsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListConfigsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListConfigsOK creates a ListConfigsOK with default headers values
func NewListConfigsOK() *ListConfigsOK {
	return &ListConfigsOK{}
}

/* ListConfigsOK describes a response with status code 200, with default header values.

A list of configs
*/
type ListConfigsOK struct {
	Payload *rest_model.ListConfigsEnvelope
}

func (o *ListConfigsOK) Error() string {
	return fmt.Sprintf("[GET /configs][%d] listConfigsOK  %+v", 200, o.Payload)
}
func (o *ListConfigsOK) GetPayload() *rest_model.ListConfigsEnvelope {
	return o.Payload
}

func (o *ListConfigsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.ListConfigsEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListConfigsBadRequest creates a ListConfigsBadRequest with default headers values
func NewListConfigsBadRequest() *ListConfigsBadRequest {
	return &ListConfigsBadRequest{}
}

/* ListConfigsBadRequest describes a response with status code 400, with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type ListConfigsBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListConfigsBadRequest) Error() string {
	return fmt.Sprintf("[GET /configs][%d] listConfigsBadRequest  %+v", 400, o.Payload)
}
func (o *ListConfigsBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListConfigsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListConfigsUnauthorized creates a ListConfigsUnauthorized with default headers values
func NewListConfigsUnauthorized() *ListConfigsUnauthorized {
	return &ListConfigsUnauthorized{}
}

/* ListConfigsUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type ListConfigsUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListConfigsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /configs][%d] listConfigsUnauthorized  %+v", 401, o.Payload)
}
func (o *ListConfigsUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListConfigsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

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
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// ListServicePoliciesReader is a Reader for the ListServicePolicies structure.
type ListServicePoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListServicePoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListServicePoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListServicePoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListServicePoliciesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListServicePoliciesOK creates a ListServicePoliciesOK with default headers values
func NewListServicePoliciesOK() *ListServicePoliciesOK {
	return &ListServicePoliciesOK{}
}

/* ListServicePoliciesOK describes a response with status code 200, with default header values.

A list of service policies
*/
type ListServicePoliciesOK struct {
	Payload *rest_model.ListServicePoliciesEnvelope
}

func (o *ListServicePoliciesOK) Error() string {
	return fmt.Sprintf("[GET /service-policies][%d] listServicePoliciesOK  %+v", 200, o.Payload)
}
func (o *ListServicePoliciesOK) GetPayload() *rest_model.ListServicePoliciesEnvelope {
	return o.Payload
}

func (o *ListServicePoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.ListServicePoliciesEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServicePoliciesBadRequest creates a ListServicePoliciesBadRequest with default headers values
func NewListServicePoliciesBadRequest() *ListServicePoliciesBadRequest {
	return &ListServicePoliciesBadRequest{}
}

/* ListServicePoliciesBadRequest describes a response with status code 400, with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type ListServicePoliciesBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListServicePoliciesBadRequest) Error() string {
	return fmt.Sprintf("[GET /service-policies][%d] listServicePoliciesBadRequest  %+v", 400, o.Payload)
}
func (o *ListServicePoliciesBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListServicePoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServicePoliciesUnauthorized creates a ListServicePoliciesUnauthorized with default headers values
func NewListServicePoliciesUnauthorized() *ListServicePoliciesUnauthorized {
	return &ListServicePoliciesUnauthorized{}
}

/* ListServicePoliciesUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type ListServicePoliciesUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListServicePoliciesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /service-policies][%d] listServicePoliciesUnauthorized  %+v", 401, o.Payload)
}
func (o *ListServicePoliciesUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListServicePoliciesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

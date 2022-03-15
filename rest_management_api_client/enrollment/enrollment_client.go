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

package enrollment

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new enrollment API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for enrollment API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	DeleteEnrollment(params *DeleteEnrollmentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteEnrollmentOK, error)

	DetailEnrollment(params *DetailEnrollmentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DetailEnrollmentOK, error)

	ListEnrollments(params *ListEnrollmentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListEnrollmentsOK, error)

	RefreshEnrollment(params *RefreshEnrollmentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RefreshEnrollmentCreated, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  DeleteEnrollment deletes an outstanding enrollment

  Delete an outstanding enrollment by id. Requires admin access.
*/
func (a *Client) DeleteEnrollment(params *DeleteEnrollmentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteEnrollmentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteEnrollmentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteEnrollment",
		Method:             "DELETE",
		PathPattern:        "/enrollments/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteEnrollmentReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DeleteEnrollmentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteEnrollment: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DetailEnrollment retrieves an outstanding enrollment

  Retrieves a single outstanding enrollment by id. Requires admin access.
*/
func (a *Client) DetailEnrollment(params *DetailEnrollmentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DetailEnrollmentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDetailEnrollmentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "detailEnrollment",
		Method:             "GET",
		PathPattern:        "/enrollments/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DetailEnrollmentReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DetailEnrollmentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for detailEnrollment: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListEnrollments lists outstanding enrollments

  Retrieves a list of outstanding enrollments; supports filtering, sorting, and pagination. Requires admin access.

*/
func (a *Client) ListEnrollments(params *ListEnrollmentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListEnrollmentsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListEnrollmentsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listEnrollments",
		Method:             "GET",
		PathPattern:        "/enrollments",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListEnrollmentsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListEnrollmentsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listEnrollments: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RefreshEnrollment refreshes an enrollment record s expiration window

  For expired or unexpired enrollments, reset the expiration window. A new JWT will be generated and must be used for the enrollment. If the `validFrom` value is not provided it will default to now. If the `validTo` value is not provided it will default to `validFrom`  the controller's configured enrollment timeout.
*/
func (a *Client) RefreshEnrollment(params *RefreshEnrollmentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RefreshEnrollmentCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRefreshEnrollmentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "refreshEnrollment",
		Method:             "POST",
		PathPattern:        "/enrollments/{id}/refresh",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RefreshEnrollmentReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*RefreshEnrollmentCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for refreshEnrollment: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}

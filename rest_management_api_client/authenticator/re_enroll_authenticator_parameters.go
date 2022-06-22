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

package authenticator

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// NewReEnrollAuthenticatorParams creates a new ReEnrollAuthenticatorParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewReEnrollAuthenticatorParams() *ReEnrollAuthenticatorParams {
	return &ReEnrollAuthenticatorParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewReEnrollAuthenticatorParamsWithTimeout creates a new ReEnrollAuthenticatorParams object
// with the ability to set a timeout on a request.
func NewReEnrollAuthenticatorParamsWithTimeout(timeout time.Duration) *ReEnrollAuthenticatorParams {
	return &ReEnrollAuthenticatorParams{
		timeout: timeout,
	}
}

// NewReEnrollAuthenticatorParamsWithContext creates a new ReEnrollAuthenticatorParams object
// with the ability to set a context for a request.
func NewReEnrollAuthenticatorParamsWithContext(ctx context.Context) *ReEnrollAuthenticatorParams {
	return &ReEnrollAuthenticatorParams{
		Context: ctx,
	}
}

// NewReEnrollAuthenticatorParamsWithHTTPClient creates a new ReEnrollAuthenticatorParams object
// with the ability to set a custom HTTPClient for a request.
func NewReEnrollAuthenticatorParamsWithHTTPClient(client *http.Client) *ReEnrollAuthenticatorParams {
	return &ReEnrollAuthenticatorParams{
		HTTPClient: client,
	}
}

/* ReEnrollAuthenticatorParams contains all the parameters to send to the API endpoint
   for the re enroll authenticator operation.

   Typically these are written to a http.Request.
*/
type ReEnrollAuthenticatorParams struct {

	/* ID.

	   The id of the requested resource
	*/
	ID string

	/* ReEnroll.

	   A reEnrollment request
	*/
	ReEnroll *rest_model.ReEnroll

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the re enroll authenticator params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReEnrollAuthenticatorParams) WithDefaults() *ReEnrollAuthenticatorParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the re enroll authenticator params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReEnrollAuthenticatorParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the re enroll authenticator params
func (o *ReEnrollAuthenticatorParams) WithTimeout(timeout time.Duration) *ReEnrollAuthenticatorParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the re enroll authenticator params
func (o *ReEnrollAuthenticatorParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the re enroll authenticator params
func (o *ReEnrollAuthenticatorParams) WithContext(ctx context.Context) *ReEnrollAuthenticatorParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the re enroll authenticator params
func (o *ReEnrollAuthenticatorParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the re enroll authenticator params
func (o *ReEnrollAuthenticatorParams) WithHTTPClient(client *http.Client) *ReEnrollAuthenticatorParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the re enroll authenticator params
func (o *ReEnrollAuthenticatorParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the re enroll authenticator params
func (o *ReEnrollAuthenticatorParams) WithID(id string) *ReEnrollAuthenticatorParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the re enroll authenticator params
func (o *ReEnrollAuthenticatorParams) SetID(id string) {
	o.ID = id
}

// WithReEnroll adds the reEnroll to the re enroll authenticator params
func (o *ReEnrollAuthenticatorParams) WithReEnroll(reEnroll *rest_model.ReEnroll) *ReEnrollAuthenticatorParams {
	o.SetReEnroll(reEnroll)
	return o
}

// SetReEnroll adds the reEnroll to the re enroll authenticator params
func (o *ReEnrollAuthenticatorParams) SetReEnroll(reEnroll *rest_model.ReEnroll) {
	o.ReEnroll = reEnroll
}

// WriteToRequest writes these params to a swagger request
func (o *ReEnrollAuthenticatorParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}
	if o.ReEnroll != nil {
		if err := r.SetBodyParam(o.ReEnroll); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

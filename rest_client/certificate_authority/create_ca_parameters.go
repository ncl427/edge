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

package certificate_authority

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

// NewCreateCaParams creates a new CreateCaParams object
// with the default values initialized.
func NewCreateCaParams() *CreateCaParams {
	var ()
	return &CreateCaParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewCreateCaParamsWithTimeout creates a new CreateCaParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewCreateCaParamsWithTimeout(timeout time.Duration) *CreateCaParams {
	var ()
	return &CreateCaParams{

		timeout: timeout,
	}
}

// NewCreateCaParamsWithContext creates a new CreateCaParams object
// with the default values initialized, and the ability to set a context for a request
func NewCreateCaParamsWithContext(ctx context.Context) *CreateCaParams {
	var ()
	return &CreateCaParams{

		Context: ctx,
	}
}

// NewCreateCaParamsWithHTTPClient creates a new CreateCaParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewCreateCaParamsWithHTTPClient(client *http.Client) *CreateCaParams {
	var ()
	return &CreateCaParams{
		HTTPClient: client,
	}
}

/*CreateCaParams contains all the parameters to send to the API endpoint
for the create ca operation typically these are written to a http.Request
*/
type CreateCaParams struct {

	/*Body
	  A CA to create

	*/
	Body *rest_model.CaCreate

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the create ca params
func (o *CreateCaParams) WithTimeout(timeout time.Duration) *CreateCaParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create ca params
func (o *CreateCaParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create ca params
func (o *CreateCaParams) WithContext(ctx context.Context) *CreateCaParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create ca params
func (o *CreateCaParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create ca params
func (o *CreateCaParams) WithHTTPClient(client *http.Client) *CreateCaParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create ca params
func (o *CreateCaParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create ca params
func (o *CreateCaParams) WithBody(body *rest_model.CaCreate) *CreateCaParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create ca params
func (o *CreateCaParams) SetBody(body *rest_model.CaCreate) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateCaParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
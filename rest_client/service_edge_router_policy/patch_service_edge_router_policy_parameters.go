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

package service_edge_router_policy

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

// NewPatchServiceEdgeRouterPolicyParams creates a new PatchServiceEdgeRouterPolicyParams object
// with the default values initialized.
func NewPatchServiceEdgeRouterPolicyParams() *PatchServiceEdgeRouterPolicyParams {
	var ()
	return &PatchServiceEdgeRouterPolicyParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPatchServiceEdgeRouterPolicyParamsWithTimeout creates a new PatchServiceEdgeRouterPolicyParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPatchServiceEdgeRouterPolicyParamsWithTimeout(timeout time.Duration) *PatchServiceEdgeRouterPolicyParams {
	var ()
	return &PatchServiceEdgeRouterPolicyParams{

		timeout: timeout,
	}
}

// NewPatchServiceEdgeRouterPolicyParamsWithContext creates a new PatchServiceEdgeRouterPolicyParams object
// with the default values initialized, and the ability to set a context for a request
func NewPatchServiceEdgeRouterPolicyParamsWithContext(ctx context.Context) *PatchServiceEdgeRouterPolicyParams {
	var ()
	return &PatchServiceEdgeRouterPolicyParams{

		Context: ctx,
	}
}

// NewPatchServiceEdgeRouterPolicyParamsWithHTTPClient creates a new PatchServiceEdgeRouterPolicyParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPatchServiceEdgeRouterPolicyParamsWithHTTPClient(client *http.Client) *PatchServiceEdgeRouterPolicyParams {
	var ()
	return &PatchServiceEdgeRouterPolicyParams{
		HTTPClient: client,
	}
}

/*PatchServiceEdgeRouterPolicyParams contains all the parameters to send to the API endpoint
for the patch service edge router policy operation typically these are written to a http.Request
*/
type PatchServiceEdgeRouterPolicyParams struct {

	/*Body
	  A service edge policy patch object

	*/
	Body *rest_model.ServiceEdgeRouterPolicyPatch
	/*ID
	  The id of the requested resource

	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the patch service edge router policy params
func (o *PatchServiceEdgeRouterPolicyParams) WithTimeout(timeout time.Duration) *PatchServiceEdgeRouterPolicyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch service edge router policy params
func (o *PatchServiceEdgeRouterPolicyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch service edge router policy params
func (o *PatchServiceEdgeRouterPolicyParams) WithContext(ctx context.Context) *PatchServiceEdgeRouterPolicyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch service edge router policy params
func (o *PatchServiceEdgeRouterPolicyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch service edge router policy params
func (o *PatchServiceEdgeRouterPolicyParams) WithHTTPClient(client *http.Client) *PatchServiceEdgeRouterPolicyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch service edge router policy params
func (o *PatchServiceEdgeRouterPolicyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the patch service edge router policy params
func (o *PatchServiceEdgeRouterPolicyParams) WithBody(body *rest_model.ServiceEdgeRouterPolicyPatch) *PatchServiceEdgeRouterPolicyParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch service edge router policy params
func (o *PatchServiceEdgeRouterPolicyParams) SetBody(body *rest_model.ServiceEdgeRouterPolicyPatch) {
	o.Body = body
}

// WithID adds the id to the patch service edge router policy params
func (o *PatchServiceEdgeRouterPolicyParams) WithID(id string) *PatchServiceEdgeRouterPolicyParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the patch service edge router policy params
func (o *PatchServiceEdgeRouterPolicyParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *PatchServiceEdgeRouterPolicyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
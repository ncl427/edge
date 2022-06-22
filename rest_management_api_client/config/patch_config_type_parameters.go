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
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// NewPatchConfigTypeParams creates a new PatchConfigTypeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPatchConfigTypeParams() *PatchConfigTypeParams {
	return &PatchConfigTypeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPatchConfigTypeParamsWithTimeout creates a new PatchConfigTypeParams object
// with the ability to set a timeout on a request.
func NewPatchConfigTypeParamsWithTimeout(timeout time.Duration) *PatchConfigTypeParams {
	return &PatchConfigTypeParams{
		timeout: timeout,
	}
}

// NewPatchConfigTypeParamsWithContext creates a new PatchConfigTypeParams object
// with the ability to set a context for a request.
func NewPatchConfigTypeParamsWithContext(ctx context.Context) *PatchConfigTypeParams {
	return &PatchConfigTypeParams{
		Context: ctx,
	}
}

// NewPatchConfigTypeParamsWithHTTPClient creates a new PatchConfigTypeParams object
// with the ability to set a custom HTTPClient for a request.
func NewPatchConfigTypeParamsWithHTTPClient(client *http.Client) *PatchConfigTypeParams {
	return &PatchConfigTypeParams{
		HTTPClient: client,
	}
}

/* PatchConfigTypeParams contains all the parameters to send to the API endpoint
   for the patch config type operation.

   Typically these are written to a http.Request.
*/
type PatchConfigTypeParams struct {

	/* ConfigType.

	   A config-type patch object
	*/
	ConfigType *rest_model.ConfigTypePatch

	/* ID.

	   The id of the requested resource
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the patch config type params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchConfigTypeParams) WithDefaults() *PatchConfigTypeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the patch config type params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchConfigTypeParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the patch config type params
func (o *PatchConfigTypeParams) WithTimeout(timeout time.Duration) *PatchConfigTypeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch config type params
func (o *PatchConfigTypeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch config type params
func (o *PatchConfigTypeParams) WithContext(ctx context.Context) *PatchConfigTypeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch config type params
func (o *PatchConfigTypeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch config type params
func (o *PatchConfigTypeParams) WithHTTPClient(client *http.Client) *PatchConfigTypeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch config type params
func (o *PatchConfigTypeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConfigType adds the configType to the patch config type params
func (o *PatchConfigTypeParams) WithConfigType(configType *rest_model.ConfigTypePatch) *PatchConfigTypeParams {
	o.SetConfigType(configType)
	return o
}

// SetConfigType adds the configType to the patch config type params
func (o *PatchConfigTypeParams) SetConfigType(configType *rest_model.ConfigTypePatch) {
	o.ConfigType = configType
}

// WithID adds the id to the patch config type params
func (o *PatchConfigTypeParams) WithID(id string) *PatchConfigTypeParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the patch config type params
func (o *PatchConfigTypeParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *PatchConfigTypeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.ConfigType != nil {
		if err := r.SetBodyParam(o.ConfigType); err != nil {
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

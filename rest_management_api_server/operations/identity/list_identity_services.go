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

package identity

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// ListIdentityServicesHandlerFunc turns a function with the right signature into a list identity services handler
type ListIdentityServicesHandlerFunc func(ListIdentityServicesParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn ListIdentityServicesHandlerFunc) Handle(params ListIdentityServicesParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// ListIdentityServicesHandler interface for that can handle valid list identity services params
type ListIdentityServicesHandler interface {
	Handle(ListIdentityServicesParams, interface{}) middleware.Responder
}

// NewListIdentityServices creates a new http.Handler for the list identity services operation
func NewListIdentityServices(ctx *middleware.Context, handler ListIdentityServicesHandler) *ListIdentityServices {
	return &ListIdentityServices{Context: ctx, Handler: handler}
}

/* ListIdentityServices swagger:route GET /identities/{id}/services Identity listIdentityServices

List accessible services

Retrieves a list of services that the given identity has access to. Supports filtering, sorting, and pagination. Requires admin access.


*/
type ListIdentityServices struct {
	Context *middleware.Context
	Handler ListIdentityServicesHandler
}

func (o *ListIdentityServices) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewListIdentityServicesParams()
	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		*r = *aCtx
	}
	var principal interface{}
	if uprinc != nil {
		principal = uprinc.(interface{}) // this is really a interface{}, I promise
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}

/*
	Copyright 2019 Netfoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package routes

import (
	"github.com/netfoundry/ziti-edge/edge/controller/env"
	"github.com/netfoundry/ziti-edge/edge/controller/internal/permissions"
	"github.com/netfoundry/ziti-edge/edge/controller/response"
)

func init() {
	r := NewEdgeRouterRouter()
	env.AddRouter(r)
}

type EdgeRouterRouter struct {
	BasePath       string
	BasePathLegacy string
	IdType         response.IdType
}

func NewEdgeRouterRouter() *EdgeRouterRouter {
	return &EdgeRouterRouter{
		BasePath:       "/" + EntityNameEdgeRouter,
		BasePathLegacy: "/" + EntityNameGateway,
		IdType:         response.IdTypeString,
	}
}

func (ir *EdgeRouterRouter) Register(ae *env.AppEnv) {
	registerCrudRouter(ae, ae.RootRouter, ir.BasePath, ir, permissions.IsAdmin())
	registerCrudRouter(ae, ae.RootRouter, ir.BasePathLegacy, ir, permissions.IsAdmin())
}

func (ir *EdgeRouterRouter) List(ae *env.AppEnv, rc *response.RequestContext) {
	ListWithHandler(ae, rc, ae.Handlers.EdgeRouter, MapEdgeRouterToApiEntity)
}

func (ir *EdgeRouterRouter) Detail(ae *env.AppEnv, rc *response.RequestContext) {
	DetailWithHandler(ae, rc, ae.Handlers.EdgeRouter, MapEdgeRouterToApiEntity, ir.IdType)
}

func (ir *EdgeRouterRouter) Create(ae *env.AppEnv, rc *response.RequestContext) {
	apiEntity := &EdgeRouterApi{}
	linkBuilder := (&EdgeRouterApiList{}).BuildSelfLink
	Create(rc, rc.RequestResponder, ae.Schemes.EdgeRouter.Post, apiEntity, linkBuilder, func() (string, error) {
		return ae.Handlers.EdgeRouter.HandleCreate(apiEntity.ToModel(""))
	})
}

func (ir *EdgeRouterRouter) Delete(ae *env.AppEnv, rc *response.RequestContext) {
	DeleteWithHandler(rc, ir.IdType, ae.Handlers.EdgeRouter)
}

func (ir *EdgeRouterRouter) Update(ae *env.AppEnv, rc *response.RequestContext) {
	apiEntity := &EdgeRouterApi{}
	Update(rc, ae.Schemes.EdgeRouter.Put, ir.IdType, apiEntity, func(id string) error {
		return ae.Handlers.EdgeRouter.HandleUpdate(apiEntity.ToModel(id), true)
	})
}

func (ir *EdgeRouterRouter) Patch(ae *env.AppEnv, rc *response.RequestContext) {
	apiEntity := &EdgeRouterApi{}
	Patch(rc, ae.Schemes.EdgeRouter.Patch, ir.IdType, apiEntity, func(id string, fields JsonFields) error {
		return ae.Handlers.EdgeRouter.HandlePatch(apiEntity.ToModel(id), fields)
	})
}
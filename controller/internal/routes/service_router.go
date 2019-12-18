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
	"fmt"
	"github.com/gorilla/mux"
	"github.com/netfoundry/ziti-edge/controller/env"
	"github.com/netfoundry/ziti-edge/controller/internal/permissions"
	"github.com/netfoundry/ziti-edge/controller/model"
	"github.com/netfoundry/ziti-edge/controller/persistence"
	"github.com/netfoundry/ziti-edge/controller/response"
	"net/http"
)

func init() {
	r := NewServiceRouter()
	env.AddRouter(r)
}

type ServiceRouter struct {
	BasePath string
	IdType   response.IdType
}

func NewServiceRouter() *ServiceRouter {
	return &ServiceRouter{
		BasePath: "/" + EntityNameService,
		IdType:   response.IdTypeUuid,
	}
}

func (ir *ServiceRouter) Register(ae *env.AppEnv) {
	sr := registerCrudRouter(ae, ae.RootRouter, ir.BasePath, ir, &crudResolvers{
		Create:  permissions.IsAdmin(),
		Read:    permissions.IsAuthenticated(),
		Update:  permissions.IsAdmin(),
		Delete:  permissions.IsAdmin(),
		Default: permissions.IsAdmin(),
	})

	ir.registerEdgeRouterHandlers(ae, sr)
	ir.registerHostingIdentitiesHandlers(ae, sr)
}

func (ir *ServiceRouter) registerEdgeRouterHandlers(ae *env.AppEnv, sr *mux.Router) {
	edgeRouterUrl := fmt.Sprintf("/{%s}/%s", response.IdPropertyName, EntityNameEdgeRouter)
	edgeRouterListHandler := ae.WrapHandler(ir.ListEdgeRouters, permissions.IsAdmin())
	sr.HandleFunc(edgeRouterUrl, edgeRouterListHandler).Methods(http.MethodGet)
	sr.HandleFunc(edgeRouterUrl+"/", edgeRouterListHandler).Methods(http.MethodGet)
}

func (ir *ServiceRouter) registerHostingIdentitiesHandlers(ae *env.AppEnv, sr *mux.Router) {
	urlWithSlash := fmt.Sprintf("/{%s}/hosts", response.IdPropertyName)
	urlWithOutSlash := fmt.Sprintf("/{%s}/hosts/", response.IdPropertyName)

	listHandler := ae.WrapHandler(ir.ListHostingIdentities, permissions.IsAdmin())
	addHandler := ae.WrapHandler(ir.AddHostingIdentities, permissions.IsAdmin())
	removeBulkHandler := ae.WrapHandler(ir.RemoveHostingIdentitiesBulk, permissions.IsAdmin())
	setHandler := ae.WrapHandler(ir.SetHostingIdentities, permissions.IsAdmin())

	sr.HandleFunc(urlWithSlash, listHandler).Methods(http.MethodGet)
	sr.HandleFunc(urlWithOutSlash, listHandler).Methods(http.MethodGet)

	sr.HandleFunc(urlWithSlash, addHandler).Methods(http.MethodPut)
	sr.HandleFunc(urlWithOutSlash, addHandler).Methods(http.MethodPut)

	sr.HandleFunc(urlWithSlash, removeBulkHandler).Methods(http.MethodDelete)
	sr.HandleFunc(urlWithOutSlash, removeBulkHandler).Methods(http.MethodDelete)

	sr.HandleFunc(urlWithSlash, setHandler).Methods(http.MethodPost)
	sr.HandleFunc(urlWithOutSlash, setHandler).Methods(http.MethodPost)

	urlWithSlashWithSubId := fmt.Sprintf("/{%s}/hosts/{%s}", response.IdPropertyName, response.SubIdPropertyName)
	urlWithOutSlashWithSubId := fmt.Sprintf("/{%s}/hosts/{%s}/", response.IdPropertyName, response.SubIdPropertyName)

	removeHandler := ae.WrapHandler(ir.RemoveHostingIdentity, permissions.IsAdmin())

	sr.HandleFunc(urlWithSlashWithSubId, removeHandler).Methods(http.MethodDelete)
	sr.HandleFunc(urlWithOutSlashWithSubId, removeHandler).Methods(http.MethodDelete)

	servicePolicyUrl := fmt.Sprintf("/{%s}/%s", response.IdPropertyName, EntityNameServicePolicy)
	servicePoliciesListHandler := ae.WrapHandler(ir.ListServicePolicies, permissions.IsAdmin())

	sr.HandleFunc(servicePolicyUrl, servicePoliciesListHandler).Methods(http.MethodGet)
	sr.HandleFunc(servicePolicyUrl+"/", servicePoliciesListHandler).Methods(http.MethodGet)
}

func (ir *ServiceRouter) List(ae *env.AppEnv, rc *response.RequestContext) {
	// ListWithHandler won't do search limiting by logged in user
	List(rc, func(rc *response.RequestContext, queryOptions *model.QueryOptions) (*QueryResult, error) {
		result, err := ae.Handlers.Service.HandleListForIdentity(rc.Identity, queryOptions)
		if err != nil {
			return nil, err
		}
		services, err := MapServicesToApiEntities(ae, rc, result.Services)
		if err != nil {
			return nil, err
		}
		return NewQueryResult(services, &result.QueryMetaData), nil
	})
}

func (ir *ServiceRouter) Detail(ae *env.AppEnv, rc *response.RequestContext) {
	// DetailWithHandler won't do search limiting by logged in user
	Detail(rc, ir.IdType, func(rc *response.RequestContext, id string) (BaseApiEntity, error) {
		service, err := ae.Handlers.Service.HandleReadForIdentity(id, rc.Session.IdentityId)
		if err != nil {
			return nil, err
		}
		return MapServiceToApiEntity(ae, rc, service)
	})
}

func (ir *ServiceRouter) Create(ae *env.AppEnv, rc *response.RequestContext) {
	serviceCreate := &ServiceApiCreate{}
	Create(rc, rc.RequestResponder, ae.Schemes.Service.Post, serviceCreate, (&ServiceApiList{}).BuildSelfLink, func() (string, error) {
		return ae.Handlers.Service.HandleCreate(serviceCreate.ToModel())
	})
}

func (ir *ServiceRouter) Delete(ae *env.AppEnv, rc *response.RequestContext) {
	DeleteWithHandler(rc, ir.IdType, ae.Handlers.Service)
}

func (ir *ServiceRouter) Update(ae *env.AppEnv, rc *response.RequestContext) {
	serviceUpdate := &ServiceApiUpdate{}
	Update(rc, ae.Schemes.Service.Put, ir.IdType, serviceUpdate, func(id string) error {
		return ae.Handlers.Service.HandleUpdate(serviceUpdate.ToModel(id))
	})
}

func (ir *ServiceRouter) Patch(ae *env.AppEnv, rc *response.RequestContext) {
	serviceUpdate := &ServiceApiUpdate{}
	Patch(rc, ae.Schemes.Service.Patch, ir.IdType, serviceUpdate, func(id string, fields JsonFields) error {
		fields.ConcatNestedNames()
		return ae.Handlers.Service.HandlePatch(serviceUpdate.ToModel(id), fields)
	})
}

func (ir *ServiceRouter) ListEdgeRouters(ae *env.AppEnv, rc *response.RequestContext) {
	ListAssociations(ae, rc, ir.IdType, ae.Handlers.Service.HandleCollectEdgeRouters, MapEdgeRouterToApiEntity)
}

func (ir *ServiceRouter) ListHostingIdentities(ae *env.AppEnv, rc *response.RequestContext) {
	ListAssociations(ae, rc, ir.IdType, ae.Handlers.Service.HandleCollectHostIds, MapIdentityToApiEntity)
}

func (ir *ServiceRouter) AddHostingIdentities(ae *env.AppEnv, rc *response.RequestContext) {
	UpdateAssociationsFor(ae, rc, ir.IdType, ae.GetStores().EdgeService, model.AssociationsActionAdd, persistence.FieldServiceHostingIdentities)
}

func (ir *ServiceRouter) RemoveHostingIdentitiesBulk(ae *env.AppEnv, rc *response.RequestContext) {
	UpdateAssociationsFor(ae, rc, ir.IdType, ae.GetStores().EdgeService, model.AssociationsActionRemove, persistence.FieldServiceHostingIdentities)
}

func (ir *ServiceRouter) RemoveHostingIdentity(ae *env.AppEnv, rc *response.RequestContext) {
	RemoveAssociationFor(ae, rc, ir.IdType, ae.GetStores().EdgeService, persistence.FieldServiceHostingIdentities)
}

func (ir *ServiceRouter) SetHostingIdentities(ae *env.AppEnv, rc *response.RequestContext) {
	UpdateAssociationsFor(ae, rc, ir.IdType, ae.GetStores().EdgeService, model.AssociationsActionSet, persistence.FieldServiceHostingIdentities)
}

func (ir *ServiceRouter) ListServicePolicies(ae *env.AppEnv, rc *response.RequestContext) {
	ListAssociations(ae, rc, ir.IdType, ae.Handlers.Service.HandleCollectServicePolicies, MapServicePolicyToApiEntity)
}
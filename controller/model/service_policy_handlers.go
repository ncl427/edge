/*
	Copyright 2019 NetFoundry, Inc.

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

package model

import (
	"github.com/netfoundry/ziti-edge/controller/persistence"
	"github.com/netfoundry/ziti-foundation/storage/boltz"
)

func NewServicePolicyHandler(env Env) *ServicePolicyHandler {
	handler := &ServicePolicyHandler{
		baseHandler: baseHandler{
			env:   env,
			store: env.GetStores().ServicePolicy,
		},
	}
	handler.impl = handler
	return handler
}

type ServicePolicyHandler struct {
	baseHandler
}

func (handler *ServicePolicyHandler) newModelEntity() boltEntitySink {
	return &ServicePolicy{}
}

func (handler *ServicePolicyHandler) Create(servicePolicy *ServicePolicy) (string, error) {
	return handler.createEntity(servicePolicy)
}

func (handler *ServicePolicyHandler) Read(id string) (*ServicePolicy, error) {
	modelEntity := &ServicePolicy{}
	if err := handler.readEntity(id, modelEntity); err != nil {
		return nil, err
	}
	return modelEntity, nil
}

func (handler *ServicePolicyHandler) Update(servicePolicy *ServicePolicy) error {
	return handler.updateEntity(servicePolicy, nil)
}

func (handler *ServicePolicyHandler) Patch(servicePolicy *ServicePolicy, checker boltz.FieldChecker) error {
	return handler.patchEntity(servicePolicy, checker)
}

func (handler *ServicePolicyHandler) Delete(id string) error {
	return handler.deleteEntity(id, nil)
}

func (handler *ServicePolicyHandler) CollectServices(id string, collector func(entity BaseModelEntity)) error {
	return handler.collectAssociated(id, persistence.EntityTypeServices, handler.env.GetHandlers().Service, collector)
}

func (handler *ServicePolicyHandler) CollectIdentities(id string, collector func(entity BaseModelEntity)) error {
	return handler.collectAssociated(id, persistence.EntityTypeIdentities, handler.env.GetHandlers().Identity, collector)
}

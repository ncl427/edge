/*
	Copyright NetFoundry Inc.

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
	"fmt"
	"github.com/openziti/edge/pb/edge_cmd_pb"
	"github.com/openziti/fabric/controller/command"
	"github.com/openziti/fabric/controller/fields"
	"github.com/openziti/fabric/controller/models"
	"github.com/openziti/fabric/controller/network"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

func NewServicePolicyManager(env Env) *ServicePolicyManager {
	manager := &ServicePolicyManager{
		baseEntityManager: newBaseEntityManager(env, env.GetStores().ServicePolicy),
	}
	manager.impl = manager

	network.RegisterManagerDecoder[*ServicePolicy](env.GetHostController().GetNetwork().Managers, manager)

	return manager
}

type ServicePolicyManager struct {
	baseEntityManager
}

func (self *ServicePolicyManager) newModelEntity() edgeEntity {
	return &ServicePolicy{}
}

func (self *ServicePolicyManager) Create(entity *ServicePolicy) error {
	return network.DispatchCreate[*ServicePolicy](self, entity)
}

func (self *ServicePolicyManager) ApplyCreate(cmd *command.CreateEntityCommand[*ServicePolicy]) error {
	fmt.Println("Created Policy ------------------------", cmd.Entity)
	_, err := self.createEntity(cmd.Entity)
	return err
}

func (self *ServicePolicyManager) Update(entity *ServicePolicy, checker fields.UpdatedFields) error {
	return network.DispatchUpdate[*ServicePolicy](self, entity, checker)
}

func (self *ServicePolicyManager) ApplyUpdate(cmd *command.UpdateEntityCommand[*ServicePolicy]) error {
	return self.updateEntity(cmd.Entity, cmd.UpdatedFields)
}

func (self *ServicePolicyManager) Read(id string) (*ServicePolicy, error) {
	modelEntity := &ServicePolicy{}
	if err := self.readEntity(id, modelEntity); err != nil {
		return nil, err
	}
	return modelEntity, nil
}

func (self *ServicePolicyManager) readInTx(tx *bbolt.Tx, id string) (*ServicePolicy, error) {
	modelEntity := &ServicePolicy{}
	if err := self.readEntityInTx(tx, id, modelEntity); err != nil {
		return nil, err
	}
	return modelEntity, nil
}

func (self *ServicePolicyManager) Marshall(entity *ServicePolicy) ([]byte, error) {
	tags, err := edge_cmd_pb.EncodeTags(entity.Tags)
	if err != nil {
		return nil, err
	}

	msg := &edge_cmd_pb.ServicePolicy{
		Id:                entity.BlockID,
		Name:              entity.Name,
		Tags:              tags,
		Semantic:          entity.Semantic,
		IdentityRoles:     entity.IdentityRoles,
		ServiceRoles:      entity.ServiceRoles,
		PostureCheckRoles: entity.PostureCheckRoles,
		PolicyType:        entity.PolicyType,
	}

	return proto.Marshal(msg)
}

func (self *ServicePolicyManager) Unmarshall(bytes []byte) (*ServicePolicy, error) {
	msg := &edge_cmd_pb.ServicePolicy{}
	if err := proto.Unmarshal(bytes, msg); err != nil {
		return nil, err
	}

	return &ServicePolicy{
		BaseEntity: models.BaseEntity{
			Id:   msg.Id,
			Tags: edge_cmd_pb.DecodeTags(msg.Tags),
		},
		Name:              msg.Name,
		Semantic:          msg.Semantic,
		IdentityRoles:     msg.IdentityRoles,
		ServiceRoles:      msg.ServiceRoles,
		PostureCheckRoles: msg.PostureCheckRoles,
		PolicyType:        msg.PolicyType,
	}, nil
}

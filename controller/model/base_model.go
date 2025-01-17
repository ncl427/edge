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
	"github.com/openziti/fabric/controller/models"
	"github.com/openziti/storage/boltz"
	"go.etcd.io/bbolt"
)

type edgeEntity interface {
	models.Entity
	fillFrom(manager EntityManager, tx *bbolt.Tx, boltEntity boltz.Entity) error
	toBoltEntityForCreate(tx *bbolt.Tx, manager EntityManager) (boltz.Entity, error)
	toBoltEntityForUpdate(tx *bbolt.Tx, manager EntityManager, checker boltz.FieldChecker) (boltz.Entity, error)
}

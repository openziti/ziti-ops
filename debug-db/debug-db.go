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

package debug_db

import (
	"github.com/openziti/edge/controller/model"
	"github.com/openziti/edge/controller/persistence"
	"github.com/openziti/edge/eid"
	"github.com/openziti/fabric/controller/db"
	"github.com/openziti/fabric/controller/network"
	"github.com/openziti/storage/boltz"
	"github.com/spf13/cobra"
	"go.etcd.io/bbolt"
)

func NewDebugDbCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add-debug-admin-user </path/to/ziti-controller.db.file>",
		Short: "Adds an admin user to the given database file for debugging purposes",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			run(args[0])
		},
	}
}

func noError(err error) {
	if err != nil {
		panic(err)
	}
}

type dbProvider struct {
	db       boltz.Db
	stores   *db.Stores
	managers *network.Managers
}

func (provider *dbProvider) GetDb() boltz.Db {
	return provider.db
}

func (provider *dbProvider) GetStores() *db.Stores {
	return provider.stores
}

func (provider *dbProvider) GetManagers() *network.Managers {
	return provider.managers
}

func run(dbFile string) {
	boltDb, err := db.Open(dbFile)
	noError(err)

	fabricStores, err := db.InitStores(boltDb)
	noError(err)

	controllers := network.NewManagers(nil, nil, boltDb, fabricStores)

	dbProvider := &dbProvider{
		db:       boltDb,
		stores:   fabricStores,
		managers: controllers,
	}

	stores, err := persistence.NewBoltStores(dbProvider)
	noError(err)

	id := "7dbd3fc9-e4c8-489a-ab8f-4bbb3d768f57"
	err = dbProvider.GetDb().Update(func(tx *bbolt.Tx) error {
		identity, _ := stores.Identity.LoadOneById(tx, id)
		if identity == nil {
			identity = &persistence.Identity{
				BaseExtEntity:  boltz.BaseExtEntity{Id: id},
				Name:           "DebugAdmin",
				IdentityTypeId: "User",
				IsDefaultAdmin: false,
				IsAdmin:        true,
			}
			ctx := boltz.NewMutateContext(tx)
			if err = stores.Identity.Create(ctx, identity); err != nil {
				return err
			}

			authHandler := model.AuthenticatorManager{}
			result := authHandler.HashPassword("admin")
			authenticator := &persistence.AuthenticatorUpdb{
				Authenticator: persistence.Authenticator{
					BaseExtEntity: boltz.BaseExtEntity{
						Id: eid.New(),
					},
					Type:       "updb",
					IdentityId: id,
				},
				Username: "admin",
				Password: result.Password,
				Salt:     result.Salt,
			}
			authenticator.SubType = authenticator

			if err = stores.Authenticator.Create(ctx, authenticator); err != nil {
				return err
			}
		}

		return nil
	})
	noError(err)
}

/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"context"
	"fmt"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/trace"
)

// InventoryCommand implements the `tctl inventory` family of commands.
type InventoryCommand struct {
	config *service.Config

	serverID string

	getConnected bool

	inventoryStatus *kingpin.CmdClause
	inventoryPing   *kingpin.CmdClause
}

// Initialize allows AccessRequestCommand to plug itself into the CLI parser
func (c *InventoryCommand) Initialize(app *kingpin.Application, config *service.Config) {
	c.config = config
	inventory := app.Command("inventory", "Manage teleport instance inventory").Hidden()

	c.inventoryStatus = inventory.Command("status", "Show inventory status summary")
	c.inventoryStatus.Flag("connected", "Show locally connected instances summary").BoolVar(&c.getConnected)

	c.inventoryPing = inventory.Command("ping", "Ping locally connected instance")
	c.inventoryPing.Arg("server-id", "ID of target server").Required().StringVar(&c.serverID)
}

// TryRun takes the CLI command as an argument (like "inventory status") and executes it.
func (c *InventoryCommand) TryRun(cmd string, client auth.ClientI) (match bool, err error) {
	switch cmd {
	case c.inventoryStatus.FullCommand():
		err = c.Status(client)
	case c.inventoryPing.FullCommand():
		err = c.Ping(client)
	default:
		return false, nil
	}
	return true, trace.Wrap(err)
}

func (c *InventoryCommand) Status(client auth.ClientI) error {
	rsp, err := client.GetInventoryStatus(context.TODO(), proto.InventoryStatusRequest{
		Connected: c.getConnected,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	for _, h := range rsp.Connected {
		fmt.Printf("%+v\n", h)
	}
	return nil
}

func (c *InventoryCommand) Ping(client auth.ClientI) error {
	rsp, err := client.PingInventory(context.TODO(), proto.InventoryPingRequest{
		ServerID: c.serverID,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("Successfully pinged server %q (~%s).\n", c.serverID, rsp.Duration)
	return nil
}

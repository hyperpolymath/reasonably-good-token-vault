// SPDX-License-Identifier: PMPL-1.0-or-later
// Terraform Provider for Svalinn Vault
//
// Enables infrastructure-as-code provisioning of:
// - Users and credentials
// - MFA policies
// - Backup configurations
// - Compliance settings

package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func main() {
	var debugMode bool

	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := &plugin.ServeOpts{
		ProviderFunc: provider.Provider,
	}

	if debugMode {
		err := plugin.Debug(context.Background(), "registry.terraform.io/hyperpolymath/svalinn", opts)
		if err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	plugin.Serve(opts)
}

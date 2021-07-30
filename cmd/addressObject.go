/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

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
package cmd

import (
	"fmt"
	"github.com/fatih/color"
	forticlient "github.com/fortinetdev/forti-sdk-go/fortios/sdkcore"
	"github.com/spf13/cobra"
	"log"
)

// addressObjectCmd represents the addressObject command
var addressObjectCmd = &cobra.Command{
	Use:   "addressObject",
	Short: "Operations Related to address objects",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:
	fortios addressObject list
Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("addressObject called")
	},
}
var addressObjectListCmd = &cobra.Command{
	Use:   "list",
	Short: "List address objects",
	Long: `List address objects. For example:
	fortios addressObject list`,
	Run: func(cmd *cobra.Command, args []string) {
		fClient := getClient()
		objectAddresses, err := fClient.Client.ListFirewallObjectAddresses()
		//policyObj := &forticlient.JSONFirewallSecurityPolicy{}
		if err != nil {
			color.Red("Something went wrong")
			log.Fatalln(err)
		}
		printObjects(objectAddresses)
	},
}

func printObjects(policyMatch []forticlient.JSONFirewallObjectAddress) error {
	color.White("%s\t%s\t%s\t%s\t%s\t%s\t%s","Name","Interface","Type", "StartIP", "EndIP", "Subnet", "FQDN")
	for _, obj := range policyMatch {
		//startIp := "nil"
		//endIp := "nil"
		subnet := "nil"
		fqdn := "nil"
		associatedInf := "nil"

		returnStr := ""
		returnStr += obj.Name + "\t"

		if obj.JSONFirewallObjectAddressFqdn != nil {
			fqdn = obj.Fqdn
		}

		/* I genuinely don't know when this is.. Range?
		if obj.Type == "range???" {
			startIp = obj.StartIP
			endIp = obj.EndIP
		}*/
		if obj.Type == "ipmask" {
			subnet = obj.Subnet
		}
		if obj.Type == "fqdn" {
			fqdn = obj.Fqdn
		}
		returnStr += fmt.Sprintf("%s\t%s\t%s\t%s\t",
			obj.Type,
			associatedInf,
			subnet,
			fqdn)
		color.White(returnStr)
	}
	return nil
}
func init() {
	rootCmd.AddCommand(addressObjectCmd)
	addressObjectCmd.AddCommand(addressObjectListCmd)
}

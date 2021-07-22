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
	"github.com/fortinetdev/forti-sdk-go/fortios/sdkcore"
	"github.com/spf13/cobra"
)
//x1r7y6gywG06q9mfjtyzrqmQk8b9HG

// lookupCmd represents the lookup command
var lookupCmd = &cobra.Command{
	Use:   "lookup",
	Short: "Lookup which policy should be hit",
	Long: `Use the policy lookup feature to see if your src,dest,and port are hitting a firewall rule. For example:

	forti policy lookup 
Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		insecure := true
		config := &Config{
			Hostname: "",
			Token: "",
			Insecure: &insecure,
		}
		var fClient FortiClient

		err := CreateFortiOSClient(&fClient, config)
		if err != nil {
			fmt.Print(err)
		}
		p := &forticlient.PolicyLookupRequest{
			Destination:     "",
			DestPort:        "",
			IPVersion:       "",
			Protocol:        "",
			SourceIP:        "",
			SourceInterface: "",
		}
		fmt.Print(p)
		fClient.Client.ReadFirewallPolicyLookup(p)
	},
}

func init() {
	lookupCmd.Flags().StringP("traffic-type", "t","TCP","Traffic type. Valid Options are: TCP,UDP,SCTP")
	lookupCmd.Flags().StringP("source","s","","Source IP for the traffic.")
	lookupCmd.Flags().StringP("source-port","p","","Source Port for the traffic.")
	lookupCmd.Flags().StringP("dest","d","","Destination IP for the traffic.")
	lookupCmd.Flags().StringP("dest-port","","","Destination Port for the traffic.")
	lookupCmd.MarkFlagRequired("source")
	lookupCmd.MarkFlagRequired("dest")
	lookupCmd.MarkFlagRequired("dest-port")

	policyCmd.AddCommand(lookupCmd)
}

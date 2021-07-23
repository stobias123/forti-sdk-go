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
	"github.com/fatih/color"
	"github.com/fortinetdev/forti-sdk-go/fortios/sdkcore"
	"github.com/spf13/cobra"
	"log"
	"strconv"
)

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
	Run: lookupPolicy,
}

var trafficType string
var source string
var sourcePort int
var sourceInterface string
var destination string
var destinationPort int

func lookupPolicy(cmd *cobra.Command, args []string) {
	fClient := getClient()
	p := &forticlient.PolicyLookupRequest{
		Destination:     destination,
		DestPort:        destinationPort,
		IPVersion:       "ipv4",
		Protocol:        "TCP",
		SourceIP:        source,
		SourceInterface: sourceInterface,
	}

	policyMatch, err := fClient.Client.ReadFirewallPolicyLookup(p)
	policyObj, err := fClient.Client.ReadFirewallSecurityPolicy1(strconv.Itoa(policyMatch.PolicyID))
	//policyObj := &forticlient.JSONFirewallSecurityPolicy{}
	if err != nil {
		log.Fatalln(err)
	}
	printPolicy(policyMatch,policyObj)
}

func printPolicy(policyMatch *forticlient.PolicyLookupResult,policyObj *forticlient.JSONFirewallSecurityPolicy) error {
	if ! policyMatch.Success {
		color.Red("No Match found. Implicit Deny will be used!")
	}else {
		color.Green("Match found! Policy ID: %d",policyMatch.PolicyID)
		color.White("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s","Name","Srcintf", "Srcaddr", "Dstintf", "Dstaddr", "ApplicationList", "Action","Nat")
		color.Yellow("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
			policyObj.Name,
			policyObj.Srcintf,
			policyObj.Srcaddr,
			policyObj.Dstintf,
			policyObj.Dstaddr,
			policyObj.ApplicationList,
			policyObj.Action,
			policyObj.Nat)
	}

	return nil
}

func init() {
	lookupCmd.Flags().StringVarP(&trafficType,"traffic-type", "t","TCP","Traffic type. Valid Options are: TCP,UDP,SCTP")
	lookupCmd.Flags().StringVarP(&source,"source","s","","Source IP for the traffic.")
	lookupCmd.Flags().StringVarP(&sourceInterface,"source-interface","","port1","Source Interface for the traffic.")
	lookupCmd.Flags().StringVarP(&destination,"dest","d","","Destination IP for the traffic.")
	lookupCmd.Flags().IntVarP(&destinationPort,"dest-port","p",80,"Destination Port for the traffic.")
	lookupCmd.MarkFlagRequired("source")
	lookupCmd.MarkFlagRequired("dest")
	lookupCmd.MarkFlagRequired("dest-port")

	policyCmd.AddCommand(lookupCmd)
}

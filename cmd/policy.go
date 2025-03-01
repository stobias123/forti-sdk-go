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
	"log"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// policyCmd represents the policy command
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List Security Policies",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fClient := getClient()
		results, err := fClient.Client.GetSecurityPolicyList("root")
		if err != nil {
			color.Red("Something went wrong")
			log.Fatalln(err)
		}
		printPolicies(results)
	},
}

func printPolicies(policies []forticlient.JSONSecurityPolicyItem) error {
	writer := tabwriter.NewWriter(os.Stdout, 10, 8, 1, '\t', tabwriter.AlignRight)
	fmt.Fprintln(writer, "PolicyID\tPolicyName\tPolicyAction")
	for _, obj := range policies {
		fmt.Fprintf(writer, "%s\t%s\t%s\t\n",
			obj.PolicyID,
			obj.Name,
			obj.Action)
	}
	writer.Flush()
	fmt.Printf("\n")
	return nil
}

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policyListCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// policyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// policyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

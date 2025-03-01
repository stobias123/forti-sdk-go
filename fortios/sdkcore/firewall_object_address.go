package forticlient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
)

// JSONFirewallObjectAddressCommon contains the General parameters for Create and Update API function
type JSONFirewallObjectAddressCommon struct {
	Name              string `json:"name"`
	Type              string `json:"type"`
	Comment           string `json:"comment"`
	AssociatedIntf    string `json:"associated-interface,omitempty"`
	ShowInAddressList string `json:"visibility,omitempty"`
	AllowRouting      string `json:"allow-routing,omitempty"`
}

// JSONFirewallObjectAddressIPRange contains the IP Range parameters for Create and Update API function
type JSONFirewallObjectAddressIPRange struct {
	StartIP string `json:"start-ip,omitempty"`
	EndIP   string `json:"end-ip,omitempty"`
}

// JSONFirewallObjectAddressCountry contains the Country parameters for Create and Update API function
type JSONFirewallObjectAddressCountry struct {
	Country string `json:"country,omitempty"`
}

// JSONFirewallObjectAddressFqdn contains the FQDN parameters for Create and Update API function
type JSONFirewallObjectAddressFqdn struct {
	Fqdn string `json:"fqdn,omitempty"`
}

// JSONFirewallObjectAddressIPMask contains the Subnet parameters for Create and Update API function
type JSONFirewallObjectAddressIPMask struct {
	Subnet string `json:"subnet,omitempty"`
}

// JSONFirewallObjectAddress contains the parameters for Create and Update API function
type JSONFirewallObjectAddress struct {
	*JSONFirewallObjectAddressCommon
	*JSONFirewallObjectAddressIPRange
	*JSONFirewallObjectAddressCountry
	*JSONFirewallObjectAddressFqdn
	*JSONFirewallObjectAddressIPMask
}

// JSONCreateFirewallObjectAddressOutput contains the output results for Create API function
type JSONCreateFirewallObjectAddressOutput struct {
	Vdom       string  `json:"vdom"`
	Mkey       string  `json:"mkey"`
	Status     string  `json:"status"`
	HTTPStatus float64 `json:"http_status"`
}

// JSONUpdateFirewallObjectAddressOutput contains the output results for Update API function
// Attention: Considering scalability, the previous structure and the current structure may change differently
type JSONUpdateFirewallObjectAddressOutput struct {
	Vdom       string  `json:"vdom"`
	Mkey       string  `json:"mkey"`
	Status     string  `json:"status"`
	HTTPStatus float64 `json:"http_status"`
}

type JSONListFirewallObjectAddressOutput struct {
	HTTPMethod string `json:"http_method"`
	Revision string `json:"revision"`
	Results []JSONFirewallObjectAddress `json:"results"`
	Status     string  `json:"status"`
	HTTPStatus float64 `json:"http_status"`
}

// CreateFirewallObjectAddress API operation for FortiOS creates a new firewall address for firewall policies.
// Returns the index value of the firewall address and execution result when the request executes successfully.
// Returns error for service API and SDK errors.
// See the firewall - address chapter in the FortiOS Handbook - CLI Reference.
func (c *FortiSDKClient) CreateFirewallObjectAddress(params *JSONFirewallObjectAddress) (output *JSONCreateFirewallObjectAddressOutput, err error) {
	HTTPMethod := "POST"
	path := "/api/v2/cmdb/firewall/address"
	output = &JSONCreateFirewallObjectAddressOutput{}
	locJSON, err := json.Marshal(params)
	if err != nil {
		log.Fatal(err)
		return
	}

	bytes := bytes.NewBuffer(locJSON)
	req := c.NewRequest(HTTPMethod, path, nil, bytes)
	err = req.Send()
	if err != nil || req.HTTPResponse == nil {
		err = fmt.Errorf("cannot send request %s", err)
		return
	}

	body, err := ioutil.ReadAll(req.HTTPResponse.Body)
	req.HTTPResponse.Body.Close() //#

	if err != nil || body == nil {
		err = fmt.Errorf("cannot get response body %s", err)
		return
	}

	var result map[string]interface{}
	json.Unmarshal([]byte(string(body)), &result)

	err = fortiAPIErrorFormat(result, string(body))

	if err == nil {
		if result["vdom"] != nil {
			output.Vdom = result["vdom"].(string)
		}

		if result["mkey"] != nil {
			output.Mkey = result["mkey"].(string)
		}
	}

	return
}

// UpdateFirewallObjectAddress API operation for FortiOS updates the specified firewall address for firewall policies.
// Returns the index value of the firewall address and execution result when the request executes successfully.
// Returns error for service API and SDK errors.
// See the firewall - address chapter in the FortiOS Handbook - CLI Reference.
func (c *FortiSDKClient) UpdateFirewallObjectAddress(params *JSONFirewallObjectAddress, mkey string) (output *JSONUpdateFirewallObjectAddressOutput, err error) {
	HTTPMethod := "PUT"
	path := "/api/v2/cmdb/firewall/address"
	path += "/" + EscapeURLString(mkey)
	output = &JSONUpdateFirewallObjectAddressOutput{}
	locJSON, err := json.Marshal(params)
	if err != nil {
		log.Fatal(err)
		return
	}

	bytes := bytes.NewBuffer(locJSON)
	req := c.NewRequest(HTTPMethod, path, nil, bytes)
	err = req.Send()
	if err != nil || req.HTTPResponse == nil {
		err = fmt.Errorf("cannot send request %s", err)
		return
	}

	body, err := ioutil.ReadAll(req.HTTPResponse.Body)
	req.HTTPResponse.Body.Close() //#

	if err != nil || body == nil {
		err = fmt.Errorf("cannot get response body %s", err)
		return
	}
	log.Printf("FOS-fortios response: %s", string(body))

	var result map[string]interface{}
	json.Unmarshal([]byte(string(body)), &result)

	err = fortiAPIErrorFormat(result, string(body))

	if err == nil {
		if result["vdom"] != nil {
			output.Vdom = result["vdom"].(string)
		}

		if result["mkey"] != nil {
			output.Mkey = result["mkey"].(string)
		}
	}

	return
}

// DeleteFirewallObjectAddress API operation for FortiOS deletes the specified firewall address for firewall policies.
// Returns error for service API and SDK errors.
// See the firewall - address chapter in the FortiOS Handbook - CLI Reference.
func (c *FortiSDKClient) DeleteFirewallObjectAddress(mkey string) (err error) {
	HTTPMethod := "DELETE"
	path := "/api/v2/cmdb/firewall/address"
	path += "/" + EscapeURLString(mkey)

	req := c.NewRequest(HTTPMethod, path, nil, nil)
	err = req.Send()
	if err != nil || req.HTTPResponse == nil {
		err = fmt.Errorf("cannot send request %s", err)
		return
	}

	body, err := ioutil.ReadAll(req.HTTPResponse.Body)
	req.HTTPResponse.Body.Close() //#

	if err != nil || body == nil {
		err = fmt.Errorf("cannot get response body %s", err)
		return
	}
	log.Printf("FOS-fortios response: %s", string(body))

	var result map[string]interface{}
	json.Unmarshal([]byte(string(body)), &result)

	err = fortiAPIErrorFormat(result, string(body))

	return
}

// ReadFirewallObjectAddress API operation for FortiOS gets the firewall address for firewall policies
// with the specified index value.
// Returns the requested firewall addresses value when the request executes successfully.
// Returns error for service API and SDK errors.
// See the firewall - address chapter in the FortiOS Handbook - CLI Reference.
func (c *FortiSDKClient) ReadFirewallObjectAddress(mkey string) (output *JSONFirewallObjectAddress, err error) {
	HTTPMethod := "GET"
	path := "/api/v2/cmdb/firewall/address"
	path += "/" + EscapeURLString(mkey)

	j1 := JSONFirewallObjectAddressCommon{}
	j2 := JSONFirewallObjectAddressIPRange{}
	j3 := JSONFirewallObjectAddressCountry{}
	j4 := JSONFirewallObjectAddressFqdn{}
	j5 := JSONFirewallObjectAddressIPMask{}

	output = &JSONFirewallObjectAddress{
		JSONFirewallObjectAddressCommon:  &j1,
		JSONFirewallObjectAddressIPRange: &j2,
		JSONFirewallObjectAddressCountry: &j3,
		JSONFirewallObjectAddressFqdn:    &j4,
		JSONFirewallObjectAddressIPMask:  &j5,
	}

	req := c.NewRequest(HTTPMethod, path, nil, nil)
	err = req.Send()
	if err != nil || req.HTTPResponse == nil {
		err = fmt.Errorf("cannot send request %s", err)
		return
	}

	body, err := ioutil.ReadAll(req.HTTPResponse.Body)
	req.HTTPResponse.Body.Close() //#

	if err != nil || body == nil {
		err = fmt.Errorf("cannot get response body %s", err)
		return
	}
	log.Printf("FOS-fortios reading response: %s", string(body))

	var result map[string]interface{}
	json.Unmarshal([]byte(string(body)), &result)

	if fortiAPIHttpStatus404Checking(result) == true {
		output = nil
		return
	}

	err = fortiAPIErrorFormat(result, string(body))

	if err == nil {
		mapTmp := (result["results"].([]interface{}))[0].(map[string]interface{})

		if mapTmp == nil {
			err = fmt.Errorf("cannot get the results from the response")
			return
		}

		if mapTmp["name"] != nil {
			output.Name = mapTmp["name"].(string)
		}
		if mapTmp["type"] != nil {
			output.Type = mapTmp["type"].(string)
		} else {
			err = fmt.Errorf("cannot get the right response, type doesn't exist.")
			return
		}

		if mapTmp["subnet"] != nil {
			output.Subnet = mapTmp["subnet"].(string)
		}
		if mapTmp["start-ip"] != nil {
			output.StartIP = mapTmp["start-ip"].(string)
		}
		if mapTmp["end-ip"] != nil {
			output.EndIP = mapTmp["end-ip"].(string)
		}
		if mapTmp["fqdn"] != nil {
			output.Fqdn = mapTmp["fqdn"].(string)
		}
		if mapTmp["country"] != nil {
			output.Country = mapTmp["country"].(string)
		}
		if mapTmp["comment"] != nil {
			output.Comment = mapTmp["comment"].(string)
		}
		if mapTmp["associated-interface"] != nil {
			output.AssociatedIntf = mapTmp["associated-interface"].(string)
		}
		if mapTmp["visibility"] != nil {
			output.ShowInAddressList = mapTmp["visibility"].(string)
		}
		if mapTmp["allow-routing"] != nil {
			output.AllowRouting = mapTmp["allow-routing"].(string)
		}

		return
	}

	return
}

func (c *FortiSDKClient) ParseFirewallObject(firewallObj *JSONFirewallObjectAddress, intputIntf map[string]interface{}) (err error) {
	//mapTmp := (intputIntf["results"].([]interface{}))[0].(map[string]interface{})

	if intputIntf == nil {
		err = fmt.Errorf("cannot get the results from the response")
		return err
	}

	if intputIntf["name"] != nil {
		firewallObj.Name = intputIntf["name"].(string)
	}
	if intputIntf["type"] != nil {
		firewallObj.Type = intputIntf["type"].(string)
	} else {
		err = fmt.Errorf("cannot get the right response, type doesn't exist.")
		return err
	}

	if intputIntf["subnet"] != nil {
		firewallObj.Subnet = intputIntf["subnet"].(string)
	}
	if intputIntf["start-ip"] != nil {
		firewallObj.StartIP = intputIntf["start-ip"].(string)
	}
	if intputIntf["end-ip"] != nil {
		firewallObj.EndIP = intputIntf["end-ip"].(string)
	}
	if intputIntf["fqdn"] != nil {
		firewallObj.Fqdn = intputIntf["fqdn"].(string)
	}
	if intputIntf["country"] != nil {
		firewallObj.Country = intputIntf["country"].(string)
	}
	if intputIntf["comment"] != nil {
		firewallObj.Comment = intputIntf["comment"].(string)
	}
	if intputIntf["associated-interface"] != nil {
		firewallObj.AssociatedIntf = intputIntf["associated-interface"].(string)
	}
	if intputIntf["visibility"] != nil {
		firewallObj.ShowInAddressList = intputIntf["visibility"].(string)
	}
	if intputIntf["allow-routing"] != nil {
		firewallObj.AllowRouting = intputIntf["allow-routing"].(string)
	}

	return nil
}

func (c *FortiSDKClient) ListFirewallObjectAddresses() (out []JSONFirewallObjectAddress, err error){

	HTTPMethod := "GET"
	path := "/api/v2/cmdb/firewall/address"

	output := JSONListFirewallObjectAddressOutput{}

	req := c.NewRequest(HTTPMethod, path, nil, nil)
	err = req.Send()
	if err != nil || req.HTTPResponse == nil {
		err = fmt.Errorf("cannot send request %s", err)
		return
	}

	body, err := ioutil.ReadAll(req.HTTPResponse.Body)
	req.HTTPResponse.Body.Close() //#

	if err != nil || body == nil {
		err = fmt.Errorf("cannot get response body %s", err)
		return
	}
	//log.Printf("FOS-fortios reading response: %s", string(body))

	var result map[string]interface{}
	json.Unmarshal([]byte(string(body)), &result)

	if fortiAPIHttpStatus404Checking(result) == true {
		log.Fatalln("Problem! 404! %s", result)
		return
	}

	err = fortiAPIErrorFormat(result, string(body))
	if err != nil {
		log.Fatalln("Problem! %v", err)
	}
	err = json.Unmarshal([]byte(string(body)), &output)
	if err != nil {
		log.Fatalln("Problem! %v", err)
	}
	return output.Results, nil
}
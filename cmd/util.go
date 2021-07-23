package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	fmgclient "github.com/fortinetdev/forti-sdk-go/fortimanager/sdkcore"
	"github.com/fortinetdev/forti-sdk-go/fortios/auth"
	"github.com/fortinetdev/forti-sdk-go/fortios/sdkcore"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type Config struct {
	Hostname string
	Token    string
	Insecure *bool
	CABundle string
	Vdom     string

	FMG_Hostname string
	FMG_Username string
	FMG_Passwd   string
	FMG_Insecure *bool
	FMG_CABundle string

	PeerAuth   string
	CaCert     string
	ClientCert string
	ClientKey  string
}
// FortiClient contains the basic FortiOS SDK connection information to FortiOS
// It can be used to as a client of FortiOS for the plugin
// Now FortiClient contains two kinds of clients:
// Client is for FortiGate
// Client Fottimanager is for FortiManager
type FortiClient struct {
	//to sdk client
	Client             *forticlient.FortiSDKClient
	ClientFortimanager *fmgclient.FmgSDKClient
}


// CreateClient creates a FortiClient Object with the authentication information.
// It returns the FortiClient Object for the use when the plugin is initialized.
func (c *Config) CreateClient() (interface{}, error) {
	var fClient FortiClient

	bFOSExist := bFortiOSHostnameExist(c)
	bFMGExist := bFortiManagerHostnameExist(c)

	if bFOSExist {
		err := CreateFortiOSClient(&fClient, c)
		if err != nil {
			return nil, fmt.Errorf("Error create fortios client: %v", err)
		}
	}

	if !bFOSExist && !bFMGExist {
		return nil, fmt.Errorf("FortiOS or FortiManager, at least one of their hostnames should be set")
	}

	return &fClient, nil
}

func bFortiOSHostnameExist(c *Config) bool {
	if c.Hostname == "" {
		if os.Getenv("FORTIOS_ACCESS_HOSTNAME") == "" {
			return false
		}
	}

	return true
}

func bFortiManagerHostnameExist(c *Config) bool {
	if c.FMG_Hostname == "" {
		if os.Getenv("FORTIOS_FMG_HOSTNAME") == "" {
			return false
		}
	}

	return true
}

func CreateFortiOSClient(fClient *FortiClient, c *Config) error {
	config := &tls.Config{}

	auth := auth.NewAuth(c.Hostname, c.Token, c.CABundle, c.PeerAuth, c.CaCert, c.ClientCert, c.ClientKey, c.Vdom)

	if auth.Hostname == "" {
		_, err := auth.GetEnvHostname()
		if err != nil {
			return fmt.Errorf("Error reading Hostname")
		}
	}

	if auth.Token == "" {
		_, err := auth.GetEnvToken()
		if err != nil {
			return fmt.Errorf("Error reading Token")
		}
	}

	if auth.CABundle == "" {
		auth.GetEnvCABundle()
	}

	if auth.PeerAuth == "" {
		_, err := auth.GetEnvPeerAuth()
		if err != nil {
			return fmt.Errorf("Error reading PeerAuth")
		}
	}
	if auth.CaCert == "" {
		_, err := auth.GetEnvCaCert()
		if err != nil {
			return fmt.Errorf("Error reading CaCert")
		}
	}
	if auth.ClientCert == "" {
		_, err := auth.GetEnvClientCert()
		if err != nil {
			return fmt.Errorf("Error reading ClientCert")
		}
	}
	if auth.ClientKey == "" {
		_, err := auth.GetEnvClientKey()
		if err != nil {
			return fmt.Errorf("Error reading ClientKey")
		}
	}

	pool := x509.NewCertPool()

	if auth.CABundle != "" {
		f, err := os.Open(auth.CABundle)
		if err != nil {
			return fmt.Errorf("Error reading CA Bundle: %v", err)
		}
		defer f.Close()

		caBundle, err := ioutil.ReadAll(f)
		if err != nil {
			return fmt.Errorf("Error reading CA Bundle: %v", err)
		}

		if !pool.AppendCertsFromPEM([]byte(caBundle)) {
			return fmt.Errorf("Error reading CA Bundle")
		}
		config.RootCAs = pool
	}

	if auth.PeerAuth == "enable" {
		if auth.CaCert != "" {
			caCertFile := auth.CaCert
			caCert, err := ioutil.ReadFile(caCertFile)
			if err != nil {
				return fmt.Errorf("client ioutil.ReadFile couldn't load cacert file: %v", err)
			}

			pool.AppendCertsFromPEM(caCert)
		}

		if auth.ClientCert == "" {
			return fmt.Errorf("User Cert file doesn't exist!")
		}

		if auth.ClientKey == "" {
			return fmt.Errorf("User Key file doesn't exist!")
		}

		clientCert, err := tls.LoadX509KeyPair(auth.ClientCert, auth.ClientKey)
		if err != nil {
			return fmt.Errorf("Client ioutil.ReadFile couldn't load clientCert/clientKey file: %v", err)
		}

		config.Certificates = []tls.Certificate{clientCert}
	}

	if c.Insecure == nil {
		// defaut value for Insecure is false
		b, _ := auth.GetEnvInsecure()
		config.InsecureSkipVerify = b
	} else {
		config.InsecureSkipVerify = *c.Insecure
	}

	if config.InsecureSkipVerify == false && auth.CABundle == "" {
		return fmt.Errorf("Error getting CA Bundle, CA Bundle should be set when insecure is false")
	}

	tr := &http.Transport{
		TLSClientConfig: config,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 250,
	}

	fc, err := forticlient.NewClient(auth, client)

	if err != nil {
		return fmt.Errorf("connection error: %v", err)
	}

	fClient.Client = fc

	return nil
}

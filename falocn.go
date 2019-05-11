package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type falconClient struct {
	user     string
	token    string
	endpoint string
}

func newFalconClient(user, token string) falconClient {
	client := falconClient{
		user:     user,
		token:    token,
		endpoint: "https://falconapi.crowdstrike.com",
	}
	return client
}

type falconDeviceQuery struct {
	ids    []string
	client *falconClient
}

func (x *falconClient) newDeviceQuery(ids []string) falconDeviceQuery {
	return falconDeviceQuery{
		client: x,
		ids:    ids,
	}
}

func (x falconDeviceQuery) run() (*falconDeviceResponse, error) {
	client := &http.Client{}
	qs := url.Values{}

	for _, id := range x.ids {
		qs.Add("ids", id)
	}

	url := fmt.Sprintf("%s/devices/entities/devices/v1?%s", x.client.endpoint, qs.Encode())
	// logger.WithField("url", url).Info("GET request URL")

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "fail to create a graylog http request")

	}
	req.SetBasicAuth(x.client.user, x.client.token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "fail to send request to Graylog")
	}

	defer resp.Body.Close()
	rawData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "Fail to read response from Graylog")
	}

	var falconResp falconDeviceResponse
	if err := json.Unmarshal(rawData, &falconResp); err != nil {
		// logger.WithField("reponse", string(rawData)).Error("Unexpected response")
		return nil, errors.Wrap(err, "Fail to parse reponse of Falcon")
	}

	return &falconResp, nil
}

type falconDeviceResponse struct {
	Errors    []interface{}          `json:"errors"`
	Meta      falconMetaData         `json:"meta"`
	Resources []falconDeviceResource `json:"resources"`
}

type falconDeviceResource struct {
	AgentLoadFlags                string               `json:"agent_load_flags"`
	AgentLocalTime                string               `json:"agent_local_time"`
	AgentVersion                  string               `json:"agent_version"`
	BiosManufacturer              string               `json:"bios_manufacturer"`
	BiosVersion                   string               `json:"bios_version"`
	Cid                           string               `json:"cid"`
	ConfigIDBase                  string               `json:"config_id_base"`
	ConfigIDBuild                 string               `json:"config_id_build"`
	ConfigIDPlatform              string               `json:"config_id_platform"`
	DeviceID                      string               `json:"device_id"`
	DevicePolicies                falconDevicePolicy   `json:"device_policies"`
	ExternalIP                    string               `json:"external_ip"`
	FirstSeen                     string               `json:"first_seen"`
	Hostname                      string               `json:"hostname"`
	LastSeen                      string               `json:"last_seen"`
	LocalIP                       string               `json:"local_ip"`
	MacAddress                    string               `json:"mac_address"`
	MajorVersion                  string               `json:"major_version"`
	Meta                          falconDeviceMetaData `json:"meta"`
	MinorVersion                  string               `json:"minor_version"`
	ModifiedTimestamp             string               `json:"modified_timestamp"`
	OsVersion                     string               `json:"os_version"`
	PlatformID                    string               `json:"platform_id"`
	PlatformName                  string               `json:"platform_name"`
	Policies                      []falconPolicy       `json:"policies"`
	ProductTypeDesc               string               `json:"product_type_desc"`
	ProvisionStatus               string               `json:"provision_status"`
	SlowChangingModifiedTimestamp string               `json:"slow_changing_modified_timestamp"`
	Status                        string               `json:"status"`
	SystemManufacturer            string               `json:"system_manufacturer"`
	SystemProductName             string               `json:"system_product_name"`
}

type falconPolicy struct {
	Applied      bool   `json:"applied"`
	AppliedDate  string `json:"applied_date"`
	AssignedDate string `json:"assigned_date"`
	PolicyID     string `json:"policy_id"`
	PolicyType   string `json:"policy_type"`
	SettingsHash string `json:"settings_hash"`
}

type falconDevicePolicy struct {
	GlobalConfig falconPolicy `json:"global_config"`
	Prevention   falconPolicy `json:"prevention"`
	SensorUpdate falconPolicy `json:"sensor_update"`
}

type falconMetaData struct {
	PoweredBy string  `json:"powered_by"`
	QueryTime float64 `json:"query_time"`
	TraceID   string  `json:"trace_id"`
}

type falconDeviceMetaData struct {
	Version string `json:"version"`
}

type falconDeviceSearchResponse struct {
	Errors    []interface{}  `json:"errors"`
	Meta      falconMetaData `json:"meta"`
	Resources []string       `json:"resources"`
}

// --------------------------
// Search
//
type falconDeviceSearchFilter struct {
	key   string
	value string
}

type falconSearchDeviceQuery struct {
	filters []falconDeviceSearchFilter
	client  *falconClient
}

func (x *falconClient) newDeviceSearchQuery() falconSearchDeviceQuery {
	return falconSearchDeviceQuery{
		client: x,
	}
}

func (x falconSearchDeviceQuery) addFilter(key, value string) falconSearchDeviceQuery {
	x.filters = append(x.filters, falconDeviceSearchFilter{key, value})
	return x
}

func (x falconSearchDeviceQuery) run() (*falconDeviceSearchResponse, error) {
	client := &http.Client{}

	var filters []string
	for _, f := range x.filters {
		filters = append(filters, fmt.Sprintf("%s:'%s'", f.key, f.value))
	}

	qs := url.Values{}
	qs.Add("filter", strings.Join(filters, "+"))

	apiURL := fmt.Sprintf("%s/devices/queries/devices/v1?%s", x.client.endpoint, qs.Encode())
	// logger.WithField("url", apiURL).Info("Query")

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "fail to create a http request for Falcon")

	}
	req.SetBasicAuth(x.client.user, x.client.token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "fail to send request to Falcon")
	}

	defer resp.Body.Close()
	rawData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "Fail to read response from Falcon")
	}

	var falconResp falconDeviceSearchResponse
	if err := json.Unmarshal(rawData, &falconResp); err != nil {
		// logger.WithField("reponse", string(rawData)).Error("Unexpected response")
		return nil, errors.Wrap(err, "Fail to parse reponse of Falcon")
	}

	return &falconResp, nil
}

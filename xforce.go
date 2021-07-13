package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
	// this is an open source package already built to implement XFE API
	// "github.com/demisto/goxforce"
)

const baseURL string = "https://api.xforce.ibmcloud.com/"

// struct to hold data from the JSON API response for a given hash
type MalHash struct {
	Malware struct {
		Origins struct {
			External struct {
				Source            string    `json:"source"`
				Firstseen         time.Time `json:"firstSeen"`
				Lastseen          time.Time `json:"lastSeen"`
				Malwaretype       string    `json:"malwareType"`
				Platform          string    `json:"platform"`
				Subplatform       string    `json:"subPlatform"`
				Detectioncoverage int       `json:"detectionCoverage"`
				Family            []string  `json:"family"`
			} `json:"external"`
		} `json:"origins"`
		Type string `json:"type"`
		Md5  string `json:"md5"`
		Hash string `json:"hash"`
		Risk string `json:"risk"`
	} `json:"malware"`
	Tags []interface{} `json:"tags"`
}

type Client struct {
	key           string
	password      string
	url           string
	defaultClient *http.Client
}

type AuthAPI struct {
	Key string
	PWD string
}

var (
	basePath = filepath.Dir("xforce_config")
	fileName = filepath.Base("config.json")
	filePath = filepath.Join(basePath, fileName)
)

func newClient() *Client {
	apiKey, apiPwd := readConfigFile()
	c := Client{
		key:           apiKey,
		password:      apiPwd,
		url:           baseURL,
		defaultClient: http.DefaultClient,
	}

	return &c
}

func readConfigFile() (string, string) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal("Error reading config file")
	}

	var apiInfo AuthAPI
	err = json.Unmarshal(data, &apiInfo);
	if err != nil {
		log.Fatal("error unmarshaling file data into object")
	}

	return apiInfo.Key, apiInfo.PWD
}

func (c *Client) setReqURL(url string) {
	c.url = url
}

func formURL(hash string) *url.URL {
	reqURL, _ := url.Parse(baseURL)
	reqURL.Path += "malware/" + hash

	return reqURL
}

func getRequest(c *Client) *MalHash {
	// TODO implement parallelization (go routines)
	req, err := http.NewRequest("GET", c.url, nil)
	if err != nil {
		log.Fatalln(err)
	}
	// set our headers and key + pwd
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.key, c.password)

	resp, err := c.defaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	// if status code is bad, log as fatal and exit
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		log.Fatalln("ERROR: " + string(rune(resp.StatusCode)))
	}
	defer resp.Body.Close()

	// read JSON response
	// establish limitedreader to read body up to 1MB
	lmtReader := io.LimitReader(resp.Body, 1e+4)
	body, err := ioutil.ReadAll(lmtReader)
	if err != nil {
		log.Fatalln(err)
	}

	malwareDetails := &MalHash{}
	// takes our JSON and puts it into go struct
	err = json.Unmarshal(body, malwareDetails)
	if err != nil {
		log.Fatalln(err)
	}

	return malwareDetails
}

func getHash() string {
	fmt.Println("Please enter the hash or a list of hashes, comma-separated, you're querying for:")
	// TODO implement this for a list of hashes from CSV
	// return list of hashes, make channels from that to use goRoutines for http requests
	var hash string
	_, err := fmt.Scanln(&hash)
	if err != nil {
		log.Fatal("Error reading hash from input")
	}

	return hash
}

func output(info *MalHash) {
	fmt.Println("HASH: ", info.Malware.Hash)
	fmt.Println("HASH TYPE: ", info.Malware.Type)
	fmt.Println("FIRST SEEN: ", info.Malware.Origins.External.Firstseen)
	fmt.Println("MALWARE TYPE: ", info.Malware.Origins.External.Malwaretype)
	fmt.Println("RISK: ", info.Malware.Risk)
	fmt.Println("MALWARE FAMILY/FAMILIES: ")
	for i := range info.Malware.Origins.External.Family {
		fmt.Println(info.Malware.Origins.External.Family[i])
	}

}

// init() is our set-up code
// we check to see if the user has already provided their API Key + PWD
// if config.json does not exist,
// we prompt user for API Key + PWD and write to config.json
func init() {
	// init() only has one job: detect if the user needs to store API auth on their drive
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		makeConfigFile(basePath)
		key, pwd := getAPIAuth()
		writeToConfig(key, pwd, filePath)
		// TODO encrypt config file with hostname as key
	}
}

func writeToConfig(key string, pwd string, filePath string) {
	// store key and pwd in struct to write to file
	auth := AuthAPI{key, pwd}
	authJSON, err := json.Marshal(auth)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(authJSON))

	// err = ioutil.WriteFile(fileName, authJSON, 0777)
	err = ioutil.WriteFile(filePath, authJSON, 0777)
	if err != nil {
		log.Fatal(err)
	}
}

// gets API key + PWD from user
func getAPIAuth() (string, string) {
	var key string
	var pwd string

	fmt.Println("Welcome! Before using this tool, please provide an API Key and Password (see: " +
		"https://api.xforce.ibmcloud.com/doc/#auth)")
	fmt.Println("Key: ")
	fmt.Scanln(&key)
	fmt.Println("Password: ")
	fmt.Scanln(&pwd)

	return key, pwd
}

// makes config.json in current directory
func makeConfigFile(basePath string) {
	fmt.Println("attempting to make config file directory at " + basePath)
	// create config file
	err := os.MkdirAll(basePath, 0777)
	if err != nil {
		fmt.Println("error, file could not be created")
		return
	}

	fmt.Println("successfully made config file")
}


func main() {
	client := newClient()
	hash := getHash()
	// TODO implement channels
	reqURL := formURL(hash)
	client.setReqURL(reqURL.String())
	resp := getRequest(client)
	output(resp)
}
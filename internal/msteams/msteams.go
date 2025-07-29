// Copyright 2025 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package msteams

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/andybalholm/brotli"
)

type ResponseTokens struct {
	SkypeToken string `json:"skypeToken"`
	ExpiresIn  int    `json:"expiresIn"`
	TokenType  string `json:"tokenType"`
}

type AuthResponse struct {
	Tokens     ResponseTokens  `json:"tokens"`
	Region     string          `json:"region"`
	Partition  string          `json:"partition"`
	RegionGtms json.RawMessage `json:"regionGtms"`
}

type CredentialsResponse struct {
	Realm    string `json:"realm"`
	Username string `json:"username"`
	Password string `json:"password"`
	Expires  int    `json:"expires"`
}

type TurnCredentials struct {
	Username string
	Password string
}

var client = &http.Client{
	Timeout: time.Second * 30,
	Transport: &http.Transport{
		DisableCompression: true,
	},
}

func getSkypeToken() (string, error) {
	url := "https://teams.microsoft.com/api/authsvc/v1.0/authz/visitor"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Host", "teams.microsoft.com")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Authorization", "Bearer")
	req.Header.Set("Ms-Teams-Auth-Type", "ExplicitLogin")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("request failed with status code %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Encoding") == "br" {
		brReader := brotli.NewReader(bytes.NewReader(body))
		body, err = io.ReadAll(brReader)
		if err != nil {
			return "", err
		}
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", err
	}

	if authResp.Tokens.SkypeToken == "" {
		return "", fmt.Errorf("skypeToken not found in response")
	}

	return authResp.Tokens.SkypeToken, nil
}

func getCredentials(skypeToken string) (*CredentialsResponse, error) {
	url := "https://teams.microsoft.com/trap-exp/tokens"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Host", "teams.microsoft.com")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36")
	req.Header.Set("X-Skypetoken", skypeToken)
	req.Header.Set("Accept", "application/json, text/javascript")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("request failed with status code %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Encoding") == "br" {
		brReader := brotli.NewReader(bytes.NewReader(body))
		body, err = io.ReadAll(brReader)
		if err != nil {
			return nil, err
		}
	}

	var credResp CredentialsResponse
	if err := json.Unmarshal(body, &credResp); err != nil {
		return nil, err
	}

	return &credResp, nil
}

// GetTurnCredentials retrieves TURN credentials from Microsoft Teams
func GetTurnCredentials() (*TurnCredentials, error) {
	skypeToken, err := getSkypeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get Skype token: %v", err)
	}

	credResp, err := getCredentials(skypeToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %v", err)
	}

	return &TurnCredentials{
		Username: credResp.Username,
		Password: credResp.Password,
	}, nil
}

// SaveConfig saves the TURN credentials to a YAML file
func SaveConfig(creds *TurnCredentials, filename string) error {
	yamlContent := fmt.Sprintf("ice_servers:\n  - urls:\n      - turns:worldaz-msit.relay.teams.microsoft.com:443?transport=tcp\n    username: \"%s\"\n    credential: \"%s\"\n",
		creds.Username,
		creds.Password)

	return os.WriteFile(filename, []byte(yamlContent), 0644)
}

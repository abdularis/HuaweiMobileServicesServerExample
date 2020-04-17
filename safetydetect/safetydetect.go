package safetydetect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type HuaweiAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

const appID = "101977939"
const clientSecret = "cc92ed7852885146a7699876c37ce03d2f8345a67acef4c1547c761573766745"

// ToDo implement access token cache till the duration of expiration time
func getSafetyDetectAccessToken() (string, error) {
	data := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s", appID, clientSecret)
	r, _ := http.NewRequest("POST", "https://Login.cloud.huawei.com/oauth2/v2/token", strings.NewReader(data))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	httpClient := &http.Client{}
	resp, err := httpClient.Do(r)

	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("request access token response error")
	}

	var respData HuaweiAccessTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return "", err
	}

	return respData.AccessToken, nil
}

type UserDetectionResultRequest struct {
	AccessToken  string `json:"accessToken"`
	CaptchaToken string `json:"response"`
}

type UserDetectionResultResponse struct {
	Success bool `json:"success"`
}

func obtainUserDetectionResult(captchaToken string, accessToken string) (*UserDetectionResultResponse, error) {
	url := fmt.Sprintf("https://hirms.cloud.huawei.com/rms/v1/userRisks/verify?appId=%s", appID)
	body, _ := json.Marshal(UserDetectionResultRequest{
		AccessToken:  accessToken,
		CaptchaToken: captchaToken,
	})

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	var respData UserDetectionResultResponse
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return nil, err
	}

	return &respData, nil
}

func VerifyCaptcha(captchaToken string) (bool, error) {
	accessToken, err := getSafetyDetectAccessToken()
	if err != nil {
		return false, err
	}

	res, err := obtainUserDetectionResult(captchaToken, accessToken)
	if err != nil {
		return false, err
	}

	return res.Success, nil
}

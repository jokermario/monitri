package phone

import (
	"encoding/json"
	"github.com/jokermario/monitri/internal/entity"
	"github.com/jokermario/monitri/pkg/log"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type Service interface {
	SendSMSToMobile(to, message string) (error, bool)
}

type service struct {
	logger      log.Logger
	SMSApiUrl   string
	SMSUsername string
	SMSApiKey   string
}

func NewService(logger log.Logger, SMSApiUrl, SMSUsername, SMSApiKey string) Service {
	return service{logger, SMSApiUrl, SMSUsername, SMSApiKey}
}

type recipientsData struct {
	Cost         string `json:"cost,omitempty"`
	MessageId    string `json:"messageId,omitempty"`
	MessageParts int    `json:"messageParts,omitempty"`
	Number       string `json:"number,omitempty"`
	Status       string `json:"status,omitempty"`
	StatusCode   int    `json:"statusCode,omitempty"`
}

type smsMessageData struct {
	Message    string           `json:"Message,omitempty"`
	Recipients []recipientsData `json:"Recipients,omitempty"`
}

type responsePayload struct {
	SMSMessageData smsMessageData `json:"SMSMessageData"`
}

func (s service) SendSMSToMobile(to, message string) (error, bool) {
	data := url.Values{}
	data.Set("username", s.SMSUsername)
	data.Set("to", to)
	data.Set("message", message)

	u, _ := url.ParseRequestURI(s.SMSApiUrl)
	urlToString := u.String()

	nonce := entity.GenerateID()

	req, _ := http.NewRequest(http.MethodPost, urlToString, strings.NewReader(data.Encode()))
	req.Header.Add("apiKey", s.SMSApiKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Add("Accept", "application/json; charset=UTF-8")
	req.Header.Add("Idempotency-Key", nonce)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Errorf("Error:", err)
	}

	if resp.StatusCode == 201 {
		// read response body
		dataa, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		var responsePayload *responsePayload
		_ = json.Unmarshal(dataa, &responsePayload)
		if responsePayload.SMSMessageData.Recipients[0].StatusCode == 101 {
			return nil, true
		}

	}
	return nil, false
}

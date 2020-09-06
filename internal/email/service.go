package email

import (
	"github.com/jokermario/monitri/pkg/log"
	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type Service interface {
	SendEmail(fromInput, toInput, subject, plainText, htmlContent string) (*rest.Response, error)
}

type service struct {
	logger log.Logger
	apiKey string
}

func NewService(logger log.Logger, apiKey string) Service {
	return service{logger, apiKey}
}

func (s service) SendEmail(fromInput, toInput, subject, plainText, htmlContent string) (*rest.Response, error) {
	client := sendgrid.NewSendClient(s.apiKey)
	from := mail.NewEmail("Monitri", fromInput)
	to := mail.NewEmail("", toInput)
	message := mail.NewSingleEmail(from, subject, to, plainText, htmlContent)
	response, err := client.Send(message)
	if err != nil && response != nil {
		return response, err
	}
	return response, nil
}

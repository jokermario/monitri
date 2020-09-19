package email

import (
	"crypto/tls"
	"github.com/jokermario/monitri/pkg/log"
	gomail "gopkg.in/gomail.v2"
	//"github.com/sendgrid/rest"
	//"github.com/sendgrid/sendgrid-go"
	//"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type Service interface {
	SendEmail(fromInput, toInput, subject, plainText, htmlContent string) error
}

type service struct {
	logger log.Logger
	emailHost string
	emailHostPort int
	emailFrom string
	emailPassword string
}

func NewService(logger log.Logger, emailHost string, emailHostPort int, emailFrom, emailPassword string) Service {
	return service{logger, emailHost, emailHostPort, emailFrom,
		emailPassword}
}

func (s service) SendEmail(fromInput, toInput, subject, plainText, htmlContent string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.emailFrom)
	m.SetHeader("To", toInput)
	m.SetHeader("Subject", subject)
	_ = fromInput
	_ = plainText
	m.SetBody("text/html", htmlContent)
	d := gomail.NewDialer(s.emailHost, s.emailHostPort, s.emailFrom, s.emailPassword)
	//fixme this line should be changed to false in production as it is unsecure
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		s.logger.Errorf("an error occurred while trying send mail. The error: %s", err)
	}
	return nil
	//client := sendgrid.NewSendClient(s.apiKey)
	//from := mail.NewEmail("Monitri", fromInput)
	//to := mail.NewEmail("", toInput)
	//message := mail.NewSingleEmail(from, subject, to, plainText, htmlContent)
	//response, err := client.Send(message)
	//if err != nil && response != nil {
	//	return response, err
	//}
	//return response, nil
}

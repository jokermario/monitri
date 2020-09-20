package email

import (
	"encoding/json"
	"fmt"
	"github.com/jokermario/monitri/pkg/log"
	"io/ioutil"
	"net/http"
	"strings"

	//"github.com/sendgrid/rest"
	//"github.com/sendgrid/sendgrid-go"
	//"github.com/sendgrid/sendgrid-go/helpers/mail"
)
const mailUsername string = "40afbd4763e71812ae3266ffa6dfa366"
const mailPassword string = "d4b5d33ba9abb93ddef368bebc347d3d"
type Service interface {
	SendEmail(toInput, subject, htmlContent string) error
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

func (s service) SendEmail(toInput, subject, htmlContent string) error {
	//DIRECT MAIL USING SENDINBLUE
	type sender struct {
		Name string `json:"name"`
		Email string `json:"email"`
	}
	type to struct {
		Email string `json:"email"`
		Name string `json:"name"`
	}
	type payload struct {
		Sender sender `json:"sender"`
		To []to `json:"to"`
		Subject string `json:"subject"`
		HtmlContent string `json:"htmlContent"`
	}
	requestPayload := payload{
		Sender: sender{Name:"Monitri", Email:"monitrillc@gmail.com"},
		To: []to{{Email:toInput, Name:""}},
		Subject: subject,
		HtmlContent: htmlContent,
	}
	sentJsonPayload, err := json.Marshal(requestPayload)
	if err != nil {
		s.logger.Errorf("an error occurred while tying to build json:", err)
	}

	urll := "https://api.sendinblue.com/v3/smtp/email"
	fmt.Println(strings.NewReader(string(sentJsonPayload)))
	req, _ := http.NewRequest(http.MethodPost, urll, strings.NewReader(string(sentJsonPayload)))
	req.Header.Add( "api-key", "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" )
	req.Header.Add( "content-type", "application/json" )
	req.Header.Add( "accept", "application/json" )

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Errorf("Error:", err)
	}
	defer resp.Body.Close()
	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))
	return nil
	//MAILJET
	//mailjetClient := mailjet.NewMailjetClient(mailUsername, mailPassword)
	//messagesInfo := []mailjet.InfoMessagesV31 {
	//	mailjet.InfoMessagesV31{
	//		From: &mailjet.RecipientV31{
	//			Email: s.emailFrom,
	//			Name: "Monitri",
	//		},
	//		To: &mailjet.RecipientsV31{
	//			mailjet.RecipientV31 {
	//				Email: toInput,
	//				Name: "",
	//			},
	//		},
	//		Subject: subject,
	//		TextPart: "My first Mailjet email",
	//		HTMLPart: htmlContent,
	//		CustomID: "AppGettingStartedTest",
	//	},
	//}
	//messages := mailjet.MessagesV31{Info: messagesInfo }
	//res, err := mailjetClient.SendMailV31(&messages)
	//if err != nil {
	//	s.logger.Error(err)
	//}
	//fmt.Printf("Data: %+v\n", res)
	//return nil
	//DIRECT MAIL SENDING WITH GOMAIL
	//m := gomail.NewMessage()
	//m.SetHeader("From", m.FormatAddress(s.emailFrom, "Monitri"))
	//m.SetHeader("To", toInput)
	//m.SetHeader("Subject", subject)
	////
	//m.SetBody("text/html", htmlContent)
	//d := gomail.NewDialer(s.emailHost, s.emailHostPort, s.emailFrom, s.emailPassword)
	////fixme this line should be changed to false in production as it is unsecure
	//d.TLSConfig = &tls.Config{InsecureSkipVerify: false}
	//
	//if err := d.DialAndSend(m); err != nil {
	//	s.logger.Errorf("an error occurred while trying send mail. The error: %s", err)
	//}
	//return nil
	//SENDGRID
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

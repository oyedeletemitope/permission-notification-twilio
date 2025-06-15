package notify

import (
	"fmt"
	"log"
	"os"
	"strings"

	twilio "github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
)

func SendSMS(to string, message string) error {
	accountSid := os.Getenv("TWILIO_ACCOUNT_SID")
	authToken := os.Getenv("TWILIO_AUTH_TOKEN")
	fromNumber := os.Getenv("TWILIO_PHONE_NUMBER")

	if accountSid == "" || authToken == "" || fromNumber == "" {
		log.Println("Error: Missing Twilio credentials in environment variables")
		return fmt.Errorf("missing Twilio credentials")
	}

	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("empty phone number provided")
	}

	if !strings.HasPrefix(to, "+") {
		to = "+1" + strings.TrimPrefix(to, "1")
	}

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSid,
		Password: authToken,
	})

	params := &openapi.CreateMessageParams{}
	params.SetTo(to)
	params.SetFrom(fromNumber)
	params.SetBody(message)

	previewLength := 50
	if len(message) > previewLength {
		log.Printf("Sending SMS to %s: %s...", to, message[:previewLength])
	} else {
		log.Printf("Sending SMS to %s: %s", to, message)
	}

	resp, err := client.Api.CreateMessage(params)
	if err != nil {
		log.Printf(" Failed to send SMS: %v", err.Error())
		return err
	}

	sid := ""
	if resp.Sid != nil {
		sid = *resp.Sid
	}
	log.Printf(" SMS sent successfully! SID: %s", sid)
	return nil
}

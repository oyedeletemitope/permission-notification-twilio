package permit

import (
	"fmt"
	"permit_twilio_demo/db"
	"permit_twilio_demo/notify"
	"strconv"

	"github.com/permitio/permit-golang/pkg/enforcement"
)

func NotifyAuthorizedUsers(action, resource, message string) {
	if PermitClient == nil {
		fmt.Println("Permit client not initialized")
		return
	}

	res := enforcement.ResourceBuilder(resource).Build()

	users, err := db.GetAllUsers()
	if err != nil {
		fmt.Println("Failed to fetch users:", err)
		return
	}

	for _, user := range users {
		userRef := enforcement.UserBuilder(strconv.Itoa(user.ID)).Build()

		allowed, err := PermitClient.Check(userRef, enforcement.Action(action), res)
		if err != nil {
			fmt.Printf("Permit error for user %d: %v\n", user.ID, err)
			continue
		}

		if allowed {
			fmt.Printf(" Notifying %s (%s)\n", user.Name, user.Phone)
			notify.SendSMS(user.Phone, message)
		}
	}
}

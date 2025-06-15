package permit

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"permit_twilio_demo/db"

	"github.com/permitio/permit-golang/pkg/config"
	"github.com/permitio/permit-golang/pkg/enforcement"
	"github.com/permitio/permit-golang/pkg/models"
	"github.com/permitio/permit-golang/pkg/permit"
)

var PermitClient *permit.Client

func ptr(s string) *string {
	return &s
}

func InitPermit() {
	cfg := config.NewConfigBuilder(os.Getenv("PERMIT_API_KEY")).Build()
	PermitClient = permit.New(cfg)
	fmt.Println(" Permit client initialized")
}

func RegisterUserInPermit(id int, email, name, role string) {
	if PermitClient == nil {
		fmt.Println("Permit client not initialized")
		return
	}

	userID := strconv.Itoa(id)

	err := PermitClient.Api.Users.Delete(context.Background(), userID)
	if err != nil {
		fmt.Printf("⚠️ Could not delete user (may not exist yet): %v\n", err)
	}

	fmt.Printf("📋 Syncing to Permit: Name=%q, Email=%q, Role=%q\n", name, email, role)

	user := models.NewUserCreate(userID)
	user.Email = ptr(email)
	user.FirstName = ptr(name)
	user.Attributes = map[string]interface{}{
		"role": role,
	}

	_, err = PermitClient.SyncUser(context.Background(), *user)
	if err != nil {
		fmt.Printf("Error syncing user: %v\n", err)
		return
	}

	_, err = PermitClient.Api.Users.AssignRole(context.Background(), userID, role, "default")
	if err != nil {
		fmt.Printf("Error assigning role: %v\n", err)
		return
	}

	fmt.Printf("Synced and assigned role '%s' to user %s (%s)\n", role, name, email)
}

func CheckPermission(userID int, resourceID int, action string) bool {
	if PermitClient == nil {
		fmt.Println("Permit client is nil")
		return false
	}

	user := enforcement.UserBuilder(strconv.Itoa(userID)).Build()
	resource := enforcement.ResourceBuilder(strconv.Itoa(resourceID)).Build()
	actionObj := enforcement.Action(action)

	allowed, err := PermitClient.Check(user, actionObj, resource)
	if err != nil {
		fmt.Printf("Permit check error: %v\n", err)
		return false
	}

	return allowed
}

func GetAuthorizedUsers(action, resource string) ([]int, error) {

	res := enforcement.ResourceBuilder(resource).Build()

	users, err := db.GetAllUsers()

	if err != nil {
		return nil, err
	}

	var authorizedUserIDs []int
	for _, user := range users {

		usr := enforcement.UserBuilder(strconv.Itoa(user.ID)).Build()

		permitted, err := PermitClient.Check(usr, enforcement.Action(action), res)

		if err != nil {
			continue
		}

		if permitted {
			authorizedUserIDs = append(authorizedUserIDs, user.ID)
		}
	}

	return authorizedUserIDs, nil
}

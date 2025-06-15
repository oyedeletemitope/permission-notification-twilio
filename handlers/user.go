package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"permit_twilio_demo/db"
	"permit_twilio_demo/middleware"
	"permit_twilio_demo/notify"
	"permit_twilio_demo/permit"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var Store *sessions.CookieStore

var tmpl *template.Template // shared from main.go

// SetTemplates allows main.go to inject the parsed templates
func SetTemplates(t *template.Template) {
	tmpl = t
}

type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

func RegisterPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Use layout template consistently with other pages
		tmpl.ExecuteTemplate(w, "layout.html", map[string]any{
			"content":          "register.html",
			"is_authenticated": false,
		})
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	role := r.FormValue("role")

	// Restrict registration to only programmer and technician roles
	if role != "programmer" && role != "technician" {
		http.Error(w, "Registration is only allowed for programmer and technician roles", http.StatusForbidden)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	// 🔐 Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user := User{
		Name:     r.FormValue("name"),
		Email:    r.FormValue("email"),
		Phone:    r.FormValue("phone"),
		Role:     role,
		Password: string(hashedPassword),
	}

	var id int
	err = db.DB.QueryRow(
		`INSERT INTO users (name, email, phone, role, password) 
		 VALUES (?, ?, ?, ?, ?) RETURNING id`,
		user.Name, user.Email, user.Phone, user.Role, user.Password,
	).Scan(&id)

	if err != nil {
		log.Printf("❌ DB insert error: %v", err)
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	fmt.Printf("📋 Syncing to Permit: Name=%q, Email=%q, Role=%q\n", user.Name, user.Email, user.Role)
	permit.RegisterUserInPermit(id, user.Email, user.Name, user.Role)

	// Redirect to login page after successful registration
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func NotifyPage(w http.ResponseWriter, r *http.Request) {
	// Get current user from context
	user, ok := middleware.GetCurrentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		// Determine what roles this user can notify based on their role
		var allowedTargets []string
		var canNotifyAll bool

		switch user.Role {
		case "manager":
			// Managers can notify everyone and all individual roles
			canNotifyAll = true
			allowedTargets = []string{"programmer", "technician", "chief_programmer", "chief_technician", "manager", "employee", "hr", "finance", "security"}
		case "chief_programmer":
			// Chief programmers can only notify regular programmers (NOT other chief_programmers)
			canNotifyAll = false
			allowedTargets = []string{"programmer"}
		case "chief_technician":
			// Chief technicians can only notify regular technicians (NOT other chief_technicians)
			canNotifyAll = false
			allowedTargets = []string{"technician"}
		default:
			// Other roles cannot send notifications
			allowedTargets = []string{}
			canNotifyAll = false
		}

		tmpl.ExecuteTemplate(w, "layout.html", map[string]any{
			"content":          "notify.html",
			"is_authenticated": true,
			"user_role":        user.Role,
			"user_name":        user.Name,
			"allowed_targets":  allowedTargets,
			"can_notify_all":   canNotifyAll,
		})
		return
	}

	// Handle POST request
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	subject := r.FormValue("subject")
	message := r.FormValue("message")

	// Get selected roles (multiple checkboxes)
	selectedRoles := r.Form["target_roles"]

	if subject == "" || message == "" {
		http.Error(w, "Subject and message are required", http.StatusBadRequest)
		return
	}

	// 🔐 RBAC Permission Checks
	var hasPermission bool
	var permissionError string
	var allowedRoles []string

	switch user.Role {
	case "manager":
		// Manager can send to the demo roles
		hasPermission = true
		allowedRoles = []string{"programmer", "technician", "chief_programmer", "chief_technician"}
	case "chief_programmer":
		// Chief programmer can only send to regular programmers (NOT other chief_programmers)
		allowedRoles = []string{"programmer"}
		hasPermission = true
	case "chief_technician":
		// Chief technician can only send to regular technicians (NOT other chief_technicians)
		allowedRoles = []string{"technician"}
		hasPermission = true
	default:
		hasPermission = false
		permissionError = "Access denied: Insufficient privileges to send notifications"
	}

	// Validate selected roles against allowed roles
	if hasPermission && len(selectedRoles) > 0 {
		for _, selectedRole := range selectedRoles {
			roleAllowed := false
			for _, allowedRole := range allowedRoles {
				if selectedRole == allowedRole {
					roleAllowed = true
					break
				}
			}
			if !roleAllowed {
				hasPermission = false
				permissionError = fmt.Sprintf("You don't have permission to send notifications to role: %s", selectedRole)
				break
			}
		}
	}

	if !hasPermission {
		http.Error(w, permissionError, http.StatusForbidden)
		return
	}

	fullMessage := subject + ": " + message

	var userIDs []int
	var err error
	var recipientDescription string

	if len(selectedRoles) > 0 {
		// Send to selected roles
		userIDs, err = getUserIDsByMultipleRoles(selectedRoles)
		if len(selectedRoles) == 1 {
			recipientDescription = fmt.Sprintf("users with role '%s'", selectedRoles[0])
		} else {
			recipientDescription = fmt.Sprintf("users with roles: %s", strings.Join(selectedRoles, ", "))
		}
	} else {
		http.Error(w, "Invalid recipient selection - please select at least one role", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Failed to fetch recipients: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if len(userIDs) == 0 {
		fmt.Fprintf(w, `<div class="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded">
			<strong>Warning:</strong> No users found for the selected criteria.
		</div>`)
		return
	}

	// Send SMS to all selected users
	successCount := 0
	failCount := 0

	for _, id := range userIDs {
		var phone string
		err := db.DB.QueryRow(`SELECT phone FROM users WHERE id = ?`, id).Scan(&phone)
		if err != nil {
			fmt.Printf("⚠️ Could not find phone for user %d: %v\n", id, err)
			failCount++
			continue
		}

		if phone == "" {
			fmt.Printf("⚠️ No phone number for user %d\n", id)
			failCount++
			continue
		}

		// Send SMS
		err = notify.SendSMS(phone, fullMessage)
		if err != nil {
			fmt.Printf("⚠️ Failed to send SMS to user %d: %v\n", id, err)
			failCount++
		} else {
			successCount++
		}
	}

	// Return success/failure message
	resultHTML := fmt.Sprintf(`
		<div class="max-w-2xl mx-auto mt-8">
			<div class="bg-white rounded-lg shadow-md p-6">
				<h3 class="text-xl font-semibold text-gray-800 mb-4">📤 Notification Results</h3>
				
				<div class="space-y-3">
					<div class="flex items-center p-3 bg-green-50 border border-green-200 rounded-lg">
						<i class="fas fa-check-circle text-green-600 mr-3"></i>
						<span class="text-green-800">
							<strong>Successfully sent to %d users</strong> (%s)
						</span>
					</div>
					
					%s
					
					<div class="border-t pt-4 mt-4">
						<p class="text-gray-600"><strong>Subject:</strong> %s</p>
						<p class="text-gray-600"><strong>Message:</strong> %s</p>
					</div>
					
					<div class="flex justify-center mt-6">
						<a href="/notify" class="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition">
							<i class="fas fa-arrow-left mr-2"></i>Send Another Notification
						</a>
					</div>
				</div>
			</div>
		</div>
	`, successCount, recipientDescription, getFailureHTML(failCount), subject, message)

	fmt.Fprint(w, resultHTML)
}

// Helper function to get user IDs by multiple roles
func getUserIDsByMultipleRoles(roles []string) ([]int, error) {
	if len(roles) == 0 {
		return []int{}, nil
	}

	// Create placeholders for the IN clause
	placeholders := make([]string, len(roles))
	args := make([]interface{}, len(roles))
	for i, role := range roles {
		placeholders[i] = "?"
		args[i] = role
	}

	query := fmt.Sprintf(`SELECT id FROM users WHERE role IN (%s)`, strings.Join(placeholders, ","))
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			continue
		}
		userIDs = append(userIDs, id)
	}
	return userIDs, nil
}

// Helper function to get all user IDs
func getAllUserIDs() ([]int, error) {
	rows, err := db.DB.Query(`SELECT id FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			continue
		}
		userIDs = append(userIDs, id)
	}
	return userIDs, nil
}

// Helper function to get user IDs by role
func getUserIDsByRole(role string) ([]int, error) {
	rows, err := db.DB.Query(`SELECT id FROM users WHERE role = ?`, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			continue
		}
		userIDs = append(userIDs, id)
	}
	return userIDs, nil
}

// Helper function to generate failure HTML
func getFailureHTML(failCount int) string {
	if failCount > 0 {
		return fmt.Sprintf(`
			<div class="flex items-center p-3 bg-red-50 border border-red-200 rounded-lg">
				<i class="fas fa-exclamation-triangle text-red-600 mr-3"></i>
				<span class="text-red-800">
					<strong>Failed to send to %d users</strong> (missing phone numbers or SMS errors)
				</span>
			</div>
		`, failCount)
	}
	return ""
}

func LoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Use layout template and specify login.html as content
		tmpl.ExecuteTemplate(w, "layout.html", map[string]any{
			"content":          "login.html",
			"is_authenticated": false,
		})
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", 400)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	// Log the login attempt for debugging
	log.Printf("Login attempt for email: %s", email)

	var user db.AppUser
	var hashedPassword string

	err := db.DB.QueryRow(`
		SELECT id, name, email, phone, role, password 
		FROM users 
		WHERE email = ?`, email).
		Scan(&user.ID, &user.Name, &user.Email, &user.Phone, &user.Role, &hashedPassword)

	if err != nil {
		log.Printf("❌ Login failed - User not found: %s", email)
		http.Error(w, "User not found", 401)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) != nil {
		log.Printf("❌ Login failed - Invalid password for: %s", email)
		http.Error(w, "Invalid password", 401)
		return
	}

	// 🔁 Re-sync user and role with Permit just to be safe
	permit.RegisterUserInPermit(user.ID, user.Email, user.Name, user.Role)

	// ✅ FIXED: Use middleware.Store instead of Store
	session, err := middleware.Store.Get(r, "session")
	if err != nil {
		log.Printf("❌ Failed to get session during login: %v - creating new session", err)
		session, _ = middleware.Store.New(r, "session")
	}

	// Store user data in session
	session.Values["user_id"] = user.ID
	session.Values["user_role"] = user.Role
	session.Values["user_name"] = user.Name

	// Save session with error handling
	if err := session.Save(r, w); err != nil {
		log.Printf("❌ Failed to save session: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	// Log successful login and session values (for debugging)
	log.Printf("✅ Login successful: %s (ID: %d, Role: %s)", user.Name, user.ID, user.Role)
	log.Printf("Session after login - ID: %s, Values: %v", session.ID, session.Values)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func HomePage(w http.ResponseWriter, r *http.Request) {
	log.Printf("HomePage handler called for path: %s", r.URL.Path)

	// Get current user from context (set by middleware)
	user, ok := middleware.GetCurrentUser(r)
	if !ok {
		log.Println("No user in context, redirecting to login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Create data for template
	data := map[string]any{
		"content":          "home.html",
		"user_name":        user.Name,
		"user_role":        user.Role,
		"user_id":          user.ID,
		"is_authenticated": true, // Flag to indicate user is logged in
	}

	// Try to render the template with error handling
	log.Println("Rendering home template for user:", user.Name)
	err := tmpl.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		log.Printf("❌ Failed to render home page: %v", err)
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println("HomePage handler completed successfully")
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the session
	session, _ := Store.Get(r, "session")
	session.Values = map[interface{}]interface{}{}
	session.Options.MaxAge = -1 // This will delete the cookie
	session.Save(r, w)

	// Redirect to login page
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

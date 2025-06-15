package handlers

import (
	"fmt"
	"net/http"
	"permit_twilio_demo/db"
	"permit_twilio_demo/middleware"
	"permit_twilio_demo/notify"
)

type Request struct {
	ID          int
	RequesterID int
	Details     string
	Status      string
	Priority    string
	ApprovedBy  int
}

func SubmitRequestPage(w http.ResponseWriter, r *http.Request) {

	if Store == nil {
		http.Error(w, "Session store not initialized", http.StatusInternalServerError)
		return
	}

	session, err := Store.Get(r, "session")
	if err != nil {
		session, _ = Store.New(r, "session")
	}

	user, ok := middleware.GetCurrentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if user.Role != "programmer" && user.Role != "technician" {
		http.Error(w, "Access denied: Only programmers and technicians can submit requests", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodGet {

		var flashes []map[string]string

		if raw, ok := session.Values["flash"]; ok {
			if flashMap, ok := raw.(map[string]string); ok {
				flashes = append(flashes, flashMap)
			} else if flashMap, ok := raw.(map[interface{}]interface{}); ok {
				convertedFlash := make(map[string]string)
				for k, v := range flashMap {
					if ks, ok := k.(string); ok {
						if vs, ok := v.(string); ok {
							convertedFlash[ks] = vs
						}
					}
				}
				if len(convertedFlash) > 0 {
					flashes = append(flashes, convertedFlash)
				}
			}

			delete(session.Values, "flash")
			session.Save(r, w)
		}

		data := map[string]any{
			"content":          "submit_request.html",
			"is_authenticated": true,
			"user_role":        user.Role,
			"user_name":        user.Name,
			"flash_messages":   flashes,
		}

		err = tmpl.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, "Template error", http.StatusInternalServerError)
		}
		return
	}

	// Handle POST request
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	details := r.FormValue("details")
	priority := r.FormValue("priority")

	if details == "" {
		session.Values["flash"] = map[string]string{
			"Type":    "error",
			"Message": "Request details are required",
		}
		session.Save(r, w)
		http.Redirect(w, r, "/submit-request", http.StatusSeeOther)
		return
	}

	_, err = db.DB.Exec(
		`INSERT INTO requests (requester_id, details, status, priority) VALUES (?, ?, 'pending', ?)`,
		user.ID, details, priority,
	)
	if err != nil {
		session.Values["flash"] = map[string]string{
			"Type":    "error",
			"Message": "Failed to submit request. Please try again.",
		}
		session.Save(r, w)
		http.Redirect(w, r, "/submit-request", http.StatusSeeOther)
		return
	}

	session.Values["flash"] = map[string]string{
		"Type":    "success",
		"Message": "Your request has been submitted successfully!",
	}
	session.Save(r, w)
	http.Redirect(w, r, "/submit-request", http.StatusSeeOther)
}

func RequestListPage(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.GetCurrentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if user.Role != "manager" && user.Role != "chief_programmer" && user.Role != "chief_technician" {
		http.Error(w, "Access denied: Insufficient privileges to view requests", http.StatusForbidden)
		return
	}

	session, _ := Store.Get(r, "session")
	var flashes []map[string]string

	if raw, ok := session.Values["flash"]; ok {
		if flashMap, ok := raw.(map[string]string); ok {
			flashes = append(flashes, flashMap)
		} else if flashMap, ok := raw.(map[interface{}]interface{}); ok {
			convertedFlash := make(map[string]string)
			for k, v := range flashMap {
				if ks, ok := k.(string); ok {
					if vs, ok := v.(string); ok {
						convertedFlash[ks] = vs
					}
				}
			}
			if len(convertedFlash) > 0 {
				flashes = append(flashes, convertedFlash)
			}
		}

		delete(session.Values, "flash")
		session.Save(r, w)
	}

	var query string
	var args []interface{}

	switch user.Role {
	case "manager":
		// Manager can see all requests
		query = `SELECT r.id, r.requester_id, r.details, r.status, r.priority, 
		                u.name as requester_name, u.role as requester_role
		         FROM requests r 
		         JOIN users u ON r.requester_id = u.id 
		         ORDER BY r.id DESC`
	case "chief_programmer":

		query = `SELECT r.id, r.requester_id, r.details, r.status, r.priority, 
		                u.name as requester_name, u.role as requester_role
		         FROM requests r 
		         JOIN users u ON r.requester_id = u.id 
		         WHERE u.role = 'programmer' 
		         ORDER BY r.id DESC`
	case "chief_technician":

		query = `SELECT r.id, r.requester_id, r.details, r.status, r.priority, 
		                u.name as requester_name, u.role as requester_role
		         FROM requests r 
		         JOIN users u ON r.requester_id = u.id 
		         WHERE u.role = 'technician' 
		         ORDER BY r.id DESC`
	}

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		http.Error(w, "Failed to load requests", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var requests []map[string]any
	for rows.Next() {
		var id, requesterID int
		var details, status, priority, requesterName, requesterRole string
		err := rows.Scan(&id, &requesterID, &details, &status, &priority, &requesterName, &requesterRole)
		if err != nil {
			continue
		}

		requests = append(requests, map[string]any{
			"id":             id,
			"requester_id":   requesterID,
			"requester_name": requesterName,
			"requester_role": requesterRole,
			"details":        details,
			"status":         status,
			"priority":       priority,
		})
	}

	// Create page title based on role
	var pageTitle string
	switch user.Role {
	case "manager":
		pageTitle = "All Requests"
	case "chief_programmer":
		pageTitle = "Programmer Requests"
	case "chief_technician":
		pageTitle = "Technician Requests"
	}

	tmpl.ExecuteTemplate(w, "layout.html", map[string]any{
		"content":          "requests.html",
		"requests":         requests,
		"page_title":       pageTitle,
		"is_authenticated": true,
		"user_role":        user.Role,
		"user_name":        user.Name,
		"flash_messages":   flashes,
	})
}

func ApproveRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.GetCurrentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Check if user has management permissions
	if user.Role != "manager" && user.Role != "chief_programmer" && user.Role != "chief_technician" {
		http.Error(w, "Access denied: Insufficient privileges to approve requests", http.StatusForbidden)
		return
	}

	requestID := r.URL.Query().Get("id")
	action := r.URL.Query().Get("action")
	if requestID == "" || (action != "approve" && action != "reject") {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)
		return
	}

	var requestIDInt int
	fmt.Sscanf(requestID, "%d", &requestIDInt)

	// Check if user has permission to approve this specific request
	var requesterRole string
	err := db.DB.QueryRow(`
		SELECT u.role 
		FROM requests r 
		JOIN users u ON r.requester_id = u.id 
		WHERE r.id = ?`, requestIDInt).Scan(&requesterRole)

	if err != nil {
		session, _ := Store.Get(r, "session")
		session.Values["flash"] = map[string]string{
			"Type":    "error",
			"Message": "Request not found or access denied.",
		}
		session.Save(r, w)
		http.Redirect(w, r, "/requests", http.StatusSeeOther)
		return
	}

	canApprove := false
	switch user.Role {
	case "manager":
		canApprove = true
	case "chief_programmer":
		canApprove = (requesterRole == "programmer")
	case "chief_technician":
		canApprove = (requesterRole == "technician")
	}

	if !canApprove {
		session, _ := Store.Get(r, "session")
		session.Values["flash"] = map[string]string{
			"Type":    "error",
			"Message": fmt.Sprintf("Access denied: You can only manage requests from %s", getRoleManagementScope(user.Role)),
		}
		session.Save(r, w)
		http.Redirect(w, r, "/requests", http.StatusSeeOther)
		return
	}

	newStatus := "approved"
	if action == "reject" {
		newStatus = "rejected"
	}

	_, err = db.DB.Exec(`UPDATE requests SET status = ?, approved_by = ? WHERE id = ?`, newStatus, user.ID, requestIDInt)
	if err != nil {
		session, _ := Store.Get(r, "session")
		session.Values["flash"] = map[string]string{
			"Type":    "error",
			"Message": "Failed to update request. Please try again.",
		}
		session.Save(r, w)
		http.Redirect(w, r, "/requests", http.StatusSeeOther)
		return
	}

	var requesterID int
	var details, priority string
	err = db.DB.QueryRow(`SELECT requester_id, details, COALESCE(priority, 'medium') FROM requests WHERE id = ?`, requestIDInt).
		Scan(&requesterID, &details, &priority)

	if err == nil {
		var phone, name string
		err = db.DB.QueryRow(`SELECT phone, name FROM users WHERE id = ?`, requesterID).Scan(&phone, &name)
		if err == nil && phone != "" {
			statusMessage := "Your request has been APPROVED."
			if newStatus == "rejected" {
				statusMessage = "Your request has been REJECTED."
			}
			if len(details) > 30 {
				details = details[:30] + "..."
			}
			message := fmt.Sprintf("Hello %s, %s\nRequest: '%s'\nPriority: %s\nDecision by: %s (%s)",
				name, statusMessage, details, priority, user.Name, user.Role)
			notify.SendSMS(phone, message)
		}
	}

	session, _ := Store.Get(r, "session")
	session.Values["flash"] = map[string]string{
		"Type":    "success",
		"Message": fmt.Sprintf("Request has been %sd successfully. SMS notification sent to requester.", action),
	}
	session.Save(r, w)
	http.Redirect(w, r, "/requests", http.StatusSeeOther)
}

func getRoleManagementScope(role string) string {
	switch role {
	case "chief_programmer":
		return "programmers"
	case "chief_technician":
		return "technicians"
	case "manager":
		return "all employees"
	default:
		return "your assigned role"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

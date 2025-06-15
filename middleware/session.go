package middleware

import (
	"context"
	"log"
	"net/http"
	"permit_twilio_demo/db"

	"github.com/gorilla/sessions"
)

var Store *sessions.CookieStore

type contextKey string

const userKey contextKey = "current_user"

func WithCurrentUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		log.Printf("WithCurrentUser middleware processing: %s %s", r.Method, r.URL.Path)

		if Store == nil {
			log.Printf("Session store not initialized in middleware")
			http.Error(w, "Server configuration error", http.StatusInternalServerError)
			return
		}

		session, err := Store.Get(r, "session")
		if err != nil {
			log.Printf("Session error: %v - creating new session", err)

			session, _ = Store.New(r, "session")
		}

		log.Printf("Session ID: %s, Values: %v", session.ID, session.Values)

		userID, ok := session.Values["user_id"]
		if !ok || userID == nil {
			log.Printf("No user_id in session, redirecting to login")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		id, ok := userID.(int)
		if !ok {
			log.Printf("user_id is not an int: %v (type: %T)", userID, userID)

			session.Values = map[interface{}]interface{}{}
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Get user from database
		user, err := db.GetUserByID(id)
		if err != nil {
			log.Printf(" Failed to get user with ID %d: %v", id, err)

			session.Values = map[interface{}]interface{}{}
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), userKey, user)
		r = r.WithContext(ctx)

		log.Printf("User authenticated: %s (ID: %d, Role: %s)", user.Name, user.ID, user.Role)

		next.ServeHTTP(w, r)
	})
}

func GetCurrentUser(r *http.Request) (db.AppUser, bool) {
	u, ok := r.Context().Value(userKey).(db.AppUser)
	return u, ok
}
func LoadSessionUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		session, err := Store.Get(r, "session")
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		userID, ok := session.Values["user_id"]
		if ok {
			if id, ok := userID.(int); ok {
				user, err := db.GetUserByID(id)
				if err == nil {
					ctx := context.WithValue(r.Context(), userKey, user)
					r = r.WithContext(ctx)
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

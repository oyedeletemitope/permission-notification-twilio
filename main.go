package main

import (
	"encoding/gob"
	"html/template"
	"log"
	"net/http"
	"os"

	"permit_twilio_demo/db"
	"permit_twilio_demo/handlers"
	"permit_twilio_demo/middleware"
	"permit_twilio_demo/permit"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
)

// Register types for gob encoding (needed for session flash messages)
func init() {
	gob.Register(map[string]string{})
}

func main() {
	// Set up logging with file and line numbers for better debugging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Println("Starting server initialization...")

	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
		// Continue execution rather than fatal to allow for environment variables set outside .env
	}

	// Initialize database connection
	log.Println("Initializing database connection...")
	db.Init()

	// Initialize Permit
	log.Println("Initializing Permit...")
	permit.InitPermit()

	// Set up templates
	log.Println("Setting up templates...")
	tmpl := template.Must(template.ParseGlob("templates/*.html"))
	handlers.SetTemplates(tmpl)

	// IMPORTANT: Set up session store and share it with both handlers and middleware
	log.Println("Setting up session store...")
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		log.Println("Warning: SESSION_SECRET not set in environment, using default value")
		sessionSecret = "default-session-secret-for-development"
	}

	store := sessions.NewCookieStore([]byte(sessionSecret))

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 24,
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteDefaultMode,
	}

	handlers.Store = store
	middleware.Store = store

	log.Println("Setting up routes...")

	http.HandleFunc("/register", logRequest(handlers.RegisterPage))
	http.HandleFunc("/login", logRequest(handlers.LoginPage))
	http.HandleFunc("/logout", logRequest(handlers.LogoutHandler))

	http.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/submit-request", logRequest(withAuth(handlers.SubmitRequestPage)))

	http.HandleFunc("/requests", logRequest(withAuth(handlers.RequestListPage)))
	http.HandleFunc("/approve", logRequest(withAuth(handlers.ApproveRequest)))
	http.HandleFunc("/notify", logRequest(withAuth(handlers.NotifyPage)))
	http.HandleFunc("/", logRequest(withAuth(handlers.HomePage)))

	log.Println("Server initialization complete. Running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		next(w, r)
	}
}

func withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		middleware.WithCurrentUser(http.HandlerFunc(handler)).ServeHTTP(w, r)
	}
}

func withOptionalUser(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		middleware.LoadSessionUser(http.HandlerFunc(handler)).ServeHTTP(w, r)
	}
}

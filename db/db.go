package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

type AppUser struct {
	ID    int
	Name  string
	Email string
	Phone string
	Role  string
}

func Init() {
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		log.Fatal("DATABASE_PATH not set in .env")
	}

	var err error
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Failed to open SQLite DB: %v", err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatalf("Failed to ping DB: %v", err)
	}

	fmt.Println("Connected to SQLite DB")

	createTables()
	createManagementUsers()
}

func createTables() {

	_, err := DB.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		phone TEXT,
		role TEXT NOT NULL,
		password TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		requester_id INTEGER,
		details TEXT,
		status TEXT DEFAULT 'pending',
		priority TEXT DEFAULT 'medium',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		approved_by INTEGER
	);
	`)
	if err != nil {
		log.Fatalf("Failed to create base tables: %v", err)
	}

	var hasPriorityColumn bool
	err = DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('requests') WHERE name = 'priority'`).Scan(&hasPriorityColumn)
	if err != nil {
		log.Fatalf("Failed to check for priority column: %v", err)
	}

	if !hasPriorityColumn {
		_, err := DB.Exec(`ALTER TABLE requests ADD COLUMN priority TEXT DEFAULT 'medium'`)
		if err != nil {
			log.Fatalf("Failed to add priority column: %v", err)
		}
		log.Println("Added 'priority' column to requests table")
	}

	var hasApprovedByColumn bool
	err = DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('requests') WHERE name = 'approved_by'`).Scan(&hasApprovedByColumn)
	if err != nil {
		log.Fatalf("Failed to check for approved_by column: %v", err)
	}

	if !hasApprovedByColumn {
		_, err := DB.Exec(`ALTER TABLE requests ADD COLUMN approved_by INTEGER`)
		if err != nil {
			log.Fatalf("Failed to add approved_by column: %v", err)
		}
		log.Println("Added 'approved_by' column to requests table")
	}
}

func createManagementUsers() {
	managementUsers := []struct {
		ID       int
		Name     string
		Email    string
		Phone    string
		Role     string
		Password string
	}{
		{
			ID:       1,
			Name:     "John Manager",
			Email:    "manager@example.com",
			Phone:    "+2348028191735",
			Role:     "manager",
			Password: "manager123",
		},
		{
			ID:       2,
			Name:     "Alice Chief Programmer",
			Email:    "chief_programmer@example.com",
			Phone:    "+2348028191735",
			Role:     "chief_programmer",
			Password: "chief123",
		},
		{
			ID:       3,
			Name:     "Bob Chief Technician",
			Email:    "chief_technician@example.com",
			Phone:    "+2348028191735",
			Role:     "chief_technician",
			Password: "tech123",
		},
	}

	for _, user := range managementUsers {

		var existingID int
		err := DB.QueryRow("SELECT id FROM users WHERE email = ?", user.Email).Scan(&existingID)

		if err == sql.ErrNoRows {

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			if err != nil {
				log.Printf("Failed to hash password for %s: %v", user.Name, err)
				continue
			}

			_, err = DB.Exec(`
				INSERT INTO users (id, name, email, phone, role, password) 
				VALUES (?, ?, ?, ?, ?, ?)`,
				user.ID, user.Name, user.Email, user.Phone, user.Role, string(hashedPassword))

			if err != nil {
				log.Printf("Failed to create management user %s: %v", user.Name, err)
			} else {
				log.Printf("Created management user: %s (%s)", user.Name, user.Role)
				fmt.Printf("Login credentials - Email: %s, Password: %s\n", user.Email, user.Password)
			}
		} else if err != nil {
			log.Printf("Error checking for existing user %s: %v", user.Email, err)
		} else {
			log.Printf("Management user already exists: %s", user.Email)
		}
	}
}

func GetAllUsers() ([]AppUser, error) {
	rows, err := DB.Query("SELECT id, name, email, phone, role FROM users")
	if err != nil {
		return nil, fmt.Errorf("querying users: %w", err)
	}
	defer rows.Close()

	var users []AppUser
	for rows.Next() {
		var u AppUser
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.Phone, &u.Role); err != nil {
			return nil, fmt.Errorf("scanning user row: %w", err)
		}
		users = append(users, u)
	}
	return users, nil
}

func GetUserByID(id int) (AppUser, error) {
	var u AppUser
	err := DB.QueryRow("SELECT id, name, email, phone, role FROM users WHERE id = ?", id).
		Scan(&u.ID, &u.Name, &u.Email, &u.Phone, &u.Role)
	return u, err
}

func GetUsersByRole(role string) ([]AppUser, error) {
	rows, err := DB.Query("SELECT id, name, email, phone, role FROM users WHERE role = ?", role)
	if err != nil {
		return nil, fmt.Errorf("querying users by role: %w", err)
	}
	defer rows.Close()

	var users []AppUser
	for rows.Next() {
		var u AppUser
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.Phone, &u.Role); err != nil {
			return nil, fmt.Errorf("scanning user row: %w", err)
		}
		users = append(users, u)
	}
	return users, nil
}

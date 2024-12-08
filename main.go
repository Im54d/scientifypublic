package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"
)

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type User struct {
	UserID           int       `json:"user_id"`
	UserName         string    `json:"user_name"`
	UserSurname      string    `json:"user_surname"`
	UserEmail        string    `json:"email"`
	UserPasswordHash string    `json:"-"`
	CreatedAt        time.Time `json:"created_at"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") == "application/json" {
		handleAPILogin(w, r)
		return
	}
	handleFormLogin(w, r)
}

func handleAPILogin(w http.ResponseWriter, r *http.Request) {
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	db, err := sql.Open("postgres", "user=postgres password=123 dbname=scientify sslmode=disable")
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Database connection error",
		})
		return
	}
	defer db.Close()

	var user User
	err = db.QueryRow("SELECT user_id, user_name, user_surname, user_email, user_password_hash FROM users WHERE user_email = $1",
		loginReq.Email).Scan(&user.UserID, &user.UserName, &user.UserSurname, &user.UserEmail, &user.UserPasswordHash)

	if err == sql.ErrNoRows {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}

	// Set session cookie
	expiration := time.Now().Add(24 * time.Hour)
	cookie := http.Cookie{
		Name:     "session_token",
		Value:    fmt.Sprintf("%d", user.UserID), // In production, use proper session tokens
		Expires:  expiration,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	// Don't send password hash in response
	user.UserPasswordHash = ""

	sendJSONResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    user,
	})
}

func handleFormLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template parsing error: %v", err)
			return
		}
		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", err)
		}
		return
	}

	// Handle POST request
	email := r.FormValue("email")
	password := r.FormValue("password")

	// TODO: Add form validation here

	db, err := sql.Open("postgres", "user=postgres password=123 dbname=scientify sslmode=disable")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var user User
	err = db.QueryRow("SELECT user_id, user_name, user_surname FROM users WHERE user_email = $1 AND user_password_hash = $2",
		email, password).Scan(&user.UserID, &user.UserName, &user.UserSurname)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set session cookie
	expiration := time.Now().Add(24 * time.Hour)
	cookie := http.Cookie{
		Name:     "session_token",
		Value:    fmt.Sprintf("%d", user.UserID),
		Expires:  expiration,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/mainpage", http.StatusSeeOther)
}

func sendJSONResponse(w http.ResponseWriter, status int, response APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

func register_page(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/register.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func index_page(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling request for /index")
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	log.Printf("Template parsed successfully")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func main_page(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/mainpage.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func user_reg(w http.ResponseWriter, r *http.Request) {
	user_name := r.FormValue("name")
	user_surname := r.FormValue("surname")
	user_email := r.FormValue("email")
	user_password_hash := r.FormValue("password")

	db, err := sql.Open("postgres", "user=postgres password=123 dbname=scientify sslmode=disable")
	if err != nil {
		log.Printf("Database connection error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	stmt, err := db.Prepare("INSERT INTO users (user_name, user_surname, user_email, user_password_hash) VALUES ($1, $2, $3, $4)")
	if err != nil {
		log.Printf("Query preparation error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user_name, user_surname, user_email, user_password_hash)
	if err != nil {
		log.Printf("Query execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleRequest() {
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/", index_page)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", register_page)
	http.HandleFunc("/index", index_page)
	http.HandleFunc("/mainpage", main_page)
	http.HandleFunc("/user_reg", user_reg)

	log.Printf("Starting server on :2222")
	if err := http.ListenAndServe(":2222", nil); err != nil {
		log.Fatal(err)
	}
}

func main() {
	db, err := sql.Open("postgres", "user=postgres password=123 dbname=scientify sslmode=disable")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	fmt.Println("Database connected")
	handleRequest()
}

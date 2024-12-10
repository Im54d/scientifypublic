package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

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
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// Структура для хранения данных токена
type Claims struct {
	UserID int `json:"user_id"`
	jwt.StandardClaims
}

type contextKey string

const userIDKey = contextKey("userID")

func validateToken(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
				Success: false,
				Message: "Missing authorization token",
			})
			return
		}

		// Удаляем "Bearer " из токена
		tokenString = tokenString[len("Bearer "):]

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil {
			sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
				Success: false,
				Message: "Invalid token",
			})
			return
		}

		if !token.Valid {
			sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
				Success: false,
				Message: "Expired token",
			})
			return
		}
		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Неверное тело запроса",
		})
		return
	}

	log.Printf("Received login request: %+v\n", loginReq)

	var user User
	var err error
	err = db.QueryRow("SELECT user_id, user_name, user_surname, user_email, user_password_hash FROM users WHERE user_email = $1",
		loginReq.Email).Scan(&user.UserID, &user.UserName, &user.UserSurname, &user.UserEmail, &user.UserPasswordHash)

	if err == sql.ErrNoRows {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Неверный email или пароль",
		})
		return
	} else if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Ошибка запроса к базе данных",
		})
		return
	}

	if !checkPasswordHash(loginReq.Password, user.UserPasswordHash) {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Неверный email или пароль",
		})
		return
	}

	// Генерация токена
	token, err := generateJWT(user.UserID)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Could not generate token",
		})
		return
	}

	sendJSONResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Message: "Login successful",
		Data:    LoginResponse{Token: token, User: user},
	})
}

// Функция для генерации JWT
func generateJWT(userID int) (string, error) {
	claims := Claims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(), // Токен будет действителен 72 часа
			Issuer:    "scientify",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret := []byte(os.Getenv("JWT_SECRET")) // Секретный ключ для подписи токена
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// Функция для проверки хеша пароля
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
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

	var user User
	err := db.QueryRow("SELECT user_id, user_name, user_surname FROM users WHERE user_email = $1 AND user_password_hash = $2",
		loginReq.Email, loginReq.Password).Scan(&user.UserID, &user.UserName, &user.UserSurname)

	if err == sql.ErrNoRows {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}

	// куки
	expiration := time.Now().Add(24 * time.Hour)
	cookie := http.Cookie{
		Name:     "session_token",
		Value:    fmt.Sprintf("%d", user.UserID), // In production, use proper session tokens
		Expires:  expiration,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	// не отправлять хэшированй пароль
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

	// ПОСТ 
	email := r.FormValue("email")
	password := r.FormValue("password")

	var user User
	err := db.QueryRow("SELECT user_id, user_name, user_surname FROM users WHERE user_email = $1 AND user_password_hash = $2",
		email, password).Scan(&user.UserID, &user.UserName, &user.UserSurname)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// куки
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
	if err = db.Ping(); err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	stmt, err := db.Prepare("INSERT INTO users (user_name, user_surname, user_email, user_password_hash) VALUES ($1, $2, $3, $4)")
	if err != nil {
		log.Printf("Query preparation error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user_password_hash), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_, err = stmt.Exec(user_name, user_surname, user_email, hashedPassword)
	if err != nil {
		log.Printf("Query execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	// Здесь вы можете получить информацию о пользователе из базы данных по userID
	var user User
	err := db.QueryRow("SELECT user_id, user_name, user_surname, user_email FROM users WHERE user_id = $1", userID).Scan(&user.UserID, &user.UserName, &user.UserSurname, &user.UserEmail)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Database query error",
		})
		return
	}

	sendJSONResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    user,
	})
}

func main() {
	var err error
	dbURL := getDatabaseURL()
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()
	log.Println("Database connected")

	// ПОРТ
	port := os.Getenv("PORT")
	if port == "" {
		port = "1010"
	}

	//РОУТЕРЫ
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/", index_page)
	http.HandleFunc("/login", handleFormLogin)
	http.HandleFunc("/register", register_page)
	http.HandleFunc("/mainpage", main_page)
	http.HandleFunc("/user_reg", user_reg)
	http.HandleFunc("/api/userinfo", validateToken(userInfoHandler))
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/apilogin", handleAPILogin)

	// Запуск сервера
	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func getDatabaseURL() string {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return "postgres://postgres:123@localhost:5432/scientify?sslmode=disable"
	}
	return dbURL
}

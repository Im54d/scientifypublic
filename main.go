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
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
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
	UserEmail        string    `json:"user_email"`
	UserPasswordHash string    `json:"user_password_hash"`
	CreatedAt        time.Time `json:"created_at"`
}

type Event struct {
	EventID          int       `json:"event_id"`
	EventTitle       string    `json:"event_title"`
	EventDate        time.Time `json:"event_date"`
	EventTime        string    `json:"event_time"`
	EventLocation    string    `json:"event_location"`
	EventDescription string    `json:"event_description"`
	EventTags        string    `json:"event_tags"`
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
	jwt.RegisteredClaims
}

type contextKey string

const userIDKey contextKey = "userID"

const JWT_SECRET_KEY = "G7$k9!mP2@xQ4#zR8^tW1&jL6*eF3$hN0"

// Проверка токена
func validateToken(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			log.Printf("Cookie not found: %v", err)
			if strings.HasPrefix(r.URL.Path, "/api/") {
				// Для API-запросов возвращаем JSON
				sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Message: "Unauthorized",
				})
			} else {
				// Для обычных запросов делаем редирект
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		claims, err := parseToken(cookie.Value)
		if err != nil {
			log.Printf("Invalid token: %v", err)
			if strings.HasPrefix(r.URL.Path, "/api/") {
				sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Message: "Invalid token",
				})
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		log.Println("Error decoding login request:", err)
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Invalid request",
		})
		return
	}

	log.Println("Handling login request for email:", loginReq.Email)

	var user User
	err := db.QueryRow("SELECT user_id, user_name, user_surname, user_email, user_password_hash FROM users WHERE user_email = $1",
		loginReq.Email).Scan(&user.UserID, &user.UserName, &user.UserSurname, &user.UserEmail, &user.UserPasswordHash)

	if err != nil {
		log.Printf("Database query error: %v", err)
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}

	// Проверка пароля
	if !checkPasswordHash(loginReq.Password, user.UserPasswordHash) {
		log.Printf("Password mismatch for user ID: %d", user.UserID)
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}

	// Генерация токена
	token, err := generateJWT(user.UserID)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Token generation failed",
		})
		return
	}

	log.Printf("Setting cookie with token: %s", token)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false,  // для отладки
		Secure:   false,  // для отладки
		Expires:  time.Now().Add(24 * time.Hour),
		SameSite: http.SameSiteLaxMode,
	})

	// Отправка успешного ответа
	sendJSONResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Message: "Login successful",
		Data:    map[string]interface{}{"token": token, "user": user},
	})

	log.Printf("User ID %d logged in successfully", user.UserID)
}

// Функция для генерации JWT
func generateJWT(userID int) (string, error) {
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
			Issuer:    "scientify",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(JWT_SECRET_KEY))
	if err != nil {
		return "", err
	}
	
	log.Printf("Generated token with secret key: %s", JWT_SECRET_KEY)
	return signedToken, nil
}

// Функция для проверки хеша пароля
func checkPasswordHash(password, hash string) bool {
	log.Printf("Checking password: '%s' against hash: '%s'", password, hash)
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		log.Printf("Password check error: %v", err)
		return false
	}
	return true
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
	err := db.QueryRow("SELECT user_id, user_name, user_surname, user_password_hash FROM users WHERE user_email = $1",
		loginReq.Email).Scan(&user.UserID, &user.UserName, &user.UserSurname, &user.UserPasswordHash)

	if err == sql.ErrNoRows {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	} else if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Database query error",
		})
		return
	}

	// Use checkPasswordHash to verify the password
	if !checkPasswordHash(loginReq.Password, user.UserPasswordHash) {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}
	// Generate a new token
	_, err = generateJWT(user.UserID)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Token generation failed",
		})
		return
	}

	// Set the new token in cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    fmt.Sprintf("%d", user.UserID),
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	})

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
			return
		}
	} else if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Логика проверки учетных данных
		// Например, вызов функции для проверки логина
		if !isValidUser(email, password) { // Предположим, что есть такая функция
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Если логин успешен
		http.Redirect(w, r, "/mainpage", http.StatusSeeOther)
		return
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
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

// Функция для получения всех событий из базы данных
func getAllEvents() ([]Event, error) {
	rows, err := db.Query("SELECT event_id, event_title, event_date, event_time, event_location, event_description, event_tags FROM events")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.EventID, &event.EventTitle, &event.EventDate, &event.EventTime, &event.EventLocation, &event.EventDescription, &event.EventTags); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

// Обработчик для отображения событий
func events(w http.ResponseWriter, r *http.Request) {
	events, err := getAllEvents()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error fetching events: %v", err)
		return
	}

	tmpl, err := template.ParseFiles("templates/events.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}

	if err := tmpl.Execute(w, events); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func create_event(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Получаем данные из формы
		event_title := r.FormValue("event-title")
		event_date := r.FormValue("event-date")
		event_time := r.FormValue("event-time")
		location := r.FormValue("event-location")
		description := r.FormValue("event-description")
		tags := r.FormValue("event-tags")
		
		// Добавим логирование для отладки
		log.Printf("Received event data: title=%s, date=%s, time=%s, location=%s, description=%s, tags=%s",
			event_title, event_date, event_time, location, description, tags)

		// Подготовка SQL запроса
		stmt, err := db.Prepare(`
			INSERT INTO events (event_title, event_date, event_time, event_location, event_description, event_tags) 
			VALUES ($1, $2, $3, $4, $5, $6)
		`)
		if err != nil {
			log.Printf("Query preparation error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		// Выполнение запроса
		_, err = stmt.Exec(event_title, event_date, event_time, location, description, tags)
		if err != nil {
			log.Printf("Query execution error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Перенаправление после успешного создания
		http.Redirect(w, r, "/events", http.StatusSeeOther)
		return
	}

	// Отображение формы создания события
	tmpl, err := template.ParseFiles("templates/create_events.html")
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
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
		return
	}
}

func profile_page(w http.ResponseWriter, r *http.Request) {
	userIDValue := r.Context().Value(userIDKey)
	if userIDValue == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID, ok := userIDValue.(int)
	if !ok {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow("SELECT user_id, user_name, user_surname, user_email FROM users WHERE user_id = $1", userID).Scan(&user.UserID, &user.UserName, &user.UserSurname, &user.UserEmail)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Database query error: %v", err)
		return
	}

	tmpl, err := template.ParseFiles("templates/profile.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}

	if err := tmpl.Execute(w, user); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

// Хэширование пароля
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Проверка пароля

// Обработчик регистрации пользователя
func user_reg(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}

		// Проверяем, существует ли пользователь с таким email
		existingUser, err := findUserByEmail(user.UserEmail)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if existingUser != nil {
			sendJSONResponse(w, http.StatusConflict, APIResponse{
				Success: false,
				Message: "Пользователь с таким email уже существует",
			})
			return
		}

		// Хэширование пароля
		hashedPassword, err := hashPassword(user.UserPasswordHash)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Сохранение хэшированного пароля
		_, err = db.Exec("INSERT INTO users (user_name, user_surname, user_email, user_password_hash) VALUES ($1, $2, $3, $4)",
			user.UserName, user.UserSurname, user.UserEmail, hashedPassword)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		sendJSONResponse(w, http.StatusCreated, APIResponse{
			Success: true,
			Message: "Пользователь успешно зарегистрирован",
		})

		// Перенаправление на страницу логина после успешной регистрации
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
}

func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)
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

func findUserByEmail(email string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT user_id, user_name, user_surname, user_email FROM users WHERE user_email = $1", email).Scan(&user.UserID, &user.UserName, &user.UserSurname, &user.UserEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Пользователь не найден
		}
		return nil, err // Ошибка выполнения запроса
	}
	return &user, nil // Пользователь найден
}

func isValidUser(email, password string) bool {
	var user User
	err := db.QueryRow("SELECT user_id, user_name, user_surname, user_email, user_password_hash FROM users WHERE user_email = $1", email).Scan(&user.UserID, &user.UserName, &user.UserSurname, &user.UserEmail, &user.UserPasswordHash)

	if err == sql.ErrNoRows {
		return false // Пользователь не найден
	} else if err != nil {
		log.Printf("Error querying user: %v", err)
		return false // Ошибка выполнения запроса
	}

	// Проверка пароля
	return checkPasswordHash(password, user.UserPasswordHash)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Удаление токена из куки
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",                             // Устанавливаем пустое значение для удаления
		Expires:  time.Now().Add(-1 * time.Hour), // Устанавливаем время истечения в прошлом
		HttpOnly: true,
	})

	// Можно также удалить другие куки, если необходимо
	// http.SetCookie(w, &http.Cookie{Name: "other_cookie", Value: "", Expires: time.Now().Add(-1 * time.Hour)})

	// Перенаправление на страницу входа или главную страницу
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func main() {
	// Загрузка переменных окружения из файла .env
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}

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
	http.HandleFunc("/profile", validateToken(profile_page))
	http.HandleFunc("/api/profile", validateToken(profileHandler))
	http.HandleFunc("/events", events)
	http.HandleFunc("/create_event", create_event)
	http.HandleFunc("/logout", logoutHandler)

	// Запуск сервера
	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func getDatabaseURL() string {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://scientify_owner:PgtTJOfZ0Qr7@ep-polished-block-a9ifzvk9.gwc.azure.neon.tech/scientify?sslmode=require"
	}
	return dbURL
}

// Функция для парсинга токена
func parseToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(JWT_SECRET_KEY), nil
	})

	if err != nil {
		log.Printf("Token parsing error: %v", err)
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем userID из контекста (установленного middleware)
	userID, ok := r.Context().Value(userIDKey).(int)
	if !ok {
		log.Printf("User ID not found in context")
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	// Получаем данные пользователя из БД
	var user User
	err := db.QueryRow("SELECT user_id, user_name, user_surname, user_email FROM users WHERE user_id = $1",
		userID).Scan(&user.UserID, &user.UserName, &user.UserSurname, &user.UserEmail)

	if err != nil {
		log.Printf("Database error: %v", err)
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to fetch user data",
		})
		return
	}

	// Отправляем данные пользователя
	sendJSONResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    user,
	})
}

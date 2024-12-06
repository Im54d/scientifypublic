package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

type Users struct {
	user_id            int
	user_name          string
	user_surname       string
	user_email         string
	user_password_hash string
}

func login_page(w http.ResponseWriter, r *http.Request) {
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
	http.HandleFunc("/login", login_page)
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

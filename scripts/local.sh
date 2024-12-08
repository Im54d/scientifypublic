#!/bin/bash
export PORT=8080
export DATABASE_URL="postgres://postgres:123@localhost:5432/scientify?sslmode=disable"
go run main.go 
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	openai "github.com/sashabaranov/go-openai"
	"golang.org/x/crypto/bcrypt"

	"go-taskapi/ent"
	"go-taskapi/ent/task"
	"go-taskapi/ent/user"

	_ "github.com/mattn/go-sqlite3"
)

var jwtSecret = []byte("supersecretstring")

type contextKey string

const userCtxKey contextKey = "userID"

type CreateTaskInput struct {
	Prompt string `json:"prompt"`
}

type UpdateTaskInput struct {
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Steps       []string `json:"steps,omitempty"`
}

type OpenAITaskResponse struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
}

type AccountInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {

	client, err := ent.Open("sqlite3", "file:data.db?cache=shared&_fk=1")
	if err != nil {
		log.Fatalf("failed opening connection to sqlite: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	if err := client.Schema.Create(ctx); err != nil {
		log.Fatalf("failed creating schema resources: %v", err)
	}

	router := mux.NewRouter()

	router.HandleFunc("/register", registerHandler(client)).Methods("POST")
	router.HandleFunc("/login", loginHandler(client)).Methods("POST")

	router.Handle("/tasks", verifyTokenMiddleware(http.HandlerFunc(createTaskHandler(client)))).Methods("POST")
	router.Handle("/tasks", verifyTokenMiddleware(http.HandlerFunc(getTasksHandler(client)))).Methods("GET")
	router.Handle("/tasks/{id}", verifyTokenMiddleware(http.HandlerFunc(updateTaskHandler(client)))).Methods("PUT")
	router.Handle("/tasks/{id}", verifyTokenMiddleware(http.HandlerFunc(deleteTaskHandler(client)))).Methods("DELETE")

	fmt.Println("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func verifyTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
			return
		}
		tokenStr := parts[1]
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			http.Error(w, "Invalid user id in token", http.StatusUnauthorized)
			return
		}
		userID := int(userIDFloat)
		ctx := context.WithValue(r.Context(), userCtxKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func registerHandler(client *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input AccountInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		ctx := context.Background()
		newUser, err := client.User.
			Create().
			SetEmail(input.Email).
			SetPassword(string(hashedPassword)).
			Save(ctx)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(newUser)
	}
}

func loginHandler(client *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input AccountInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
		ctx := context.Background()
		u, err := client.User.
			Query().
			Where(user.EmailEQ(input.Email)).
			Only(ctx)
		if err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(input.Password)); err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": u.ID,
			"exp":     time.Now().Add(72 * time.Hour).Unix(),
		})
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	}
}

func createTaskHandler(client *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input CreateTaskInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
		userID, ok := r.Context().Value(userCtxKey).(int)
		if !ok {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}
		title, description, steps, err := generateTaskFromPrompt(input.Prompt)
		if err != nil {
			fmt.Println("Task generation Error: ", err)
			http.Error(w, "Failed to generate task details", http.StatusInternalServerError)
			return
		}
		ctx := context.Background()
		u, err := client.User.Get(ctx, userID)
		if err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}
		t, err := client.Task.
			Create().
			SetTitle(title).
			SetDescription(description).
			SetSteps(steps).
			SetUser(u).
			Save(ctx)
		if err != nil {
			http.Error(w, "Failed to save task", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(t)
	}
}

func getTasksHandler(client *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := r.Context().Value(userCtxKey).(int)
		if !ok {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}
		ctx := context.Background()
		tasks, err := client.Task.
			Query().
			Where(task.HasUserWith(user.IDEQ(userID))).
			All(ctx)
		if err != nil {
			http.Error(w, "Failed to retrieve tasks", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tasks)
	}
}

func updateTaskHandler(client *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		taskID, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid task ID", http.StatusBadRequest)
			return
		}

		userID, ok := r.Context().Value(userCtxKey).(int)
		if !ok {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		var input UpdateTaskInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}

		ctx := context.Background()

		t, err := client.Task.
			Query().
			Where(task.IDEQ(taskID), task.HasUserWith(user.IDEQ(userID))).
			Only(ctx)
		if err != nil {
			http.Error(w, "Task not found or unauthorized", http.StatusNotFound)
			return
		}

		update := t.Update()
		if input.Title != "" {
			update.SetTitle(input.Title)
		}
		if input.Description != "" {
			update.SetDescription(input.Description)
		}
		if input.Steps != nil {
			update.SetSteps(input.Steps)
		}

		updatedTask, err := update.Save(ctx)
		if err != nil {
			http.Error(w, "Failed to update task", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updatedTask)
	}
}

func deleteTaskHandler(client *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		taskID, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid task ID", http.StatusBadRequest)
			return
		}

		userID, ok := r.Context().Value(userCtxKey).(int)
		if !ok {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		ctx := context.Background()

		_, err = client.Task.
			Query().
			Where(task.IDEQ(taskID), task.HasUserWith(user.IDEQ(userID))).
			Only(ctx)

		if err != nil {
			http.Error(w, "Task not found or unauthorized", http.StatusNotFound)
			return
		}

		if err := client.Task.
			DeleteOneID(taskID).
			Exec(ctx); err != nil {
			http.Error(w, "Failed to delete task", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func generateTaskFromPrompt(prompt string) (string, string, []string, error) {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	if useFake := os.Getenv("USE_FAKE_AI"); useFake == "true" {
		return "Fake Task Title", "This is a fake task description based on the prompt: " + prompt, []string{"Fake step 1", "Fake step 2"}, nil
	}

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		return "", "", []string{""}, fmt.Errorf("OPENAI_API_KEY not set")
	}
	aiClient := openai.NewClient(apiKey)
	ctx := context.Background()
	req := openai.ChatCompletionRequest{
		Model: openai.GPT3Dot5Turbo,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    "system",
				Content: "You are an assistant that generates a JSON object with a title and a detailed description for a todo task, then in the object include an array of string that represents the steps you take to finish the task. Your output must be valid JSON in the following format: {\"title\": \"Task Title\", \"description\": \"Task Description\", \"steps\": [\"Step 1\", \"Step 2\"]}",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}
	resp, err := aiClient.CreateChatCompletion(ctx, req)
	if err != nil {
		return "", "", []string{""}, err
	}
	responseText := resp.Choices[0].Message.Content
	var result OpenAITaskResponse
	if err := json.Unmarshal([]byte(responseText), &result); err != nil {
		return "", "", []string{""}, fmt.Errorf("failed to parse response: %v", err)
	}
	return result.Title, result.Description, result.Steps, nil
}

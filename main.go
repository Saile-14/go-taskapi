package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	openai "github.com/sashabaranov/go-openai"
	"golang.org/x/crypto/bcrypt"

	// Import the generated ent client and schema packages.
	"go-taskapi/ent"
	"go-taskapi/ent/task"
	"go-taskapi/ent/user"

	_ "github.com/mattn/go-sqlite3"
)

// jwtSecret is used to sign JWT tokens.
var jwtSecret = []byte("your_secret_key") // Replace with your secret!

// contextKey is used for storing/retrieving values from the request context.
type contextKey string

const userCtxKey contextKey = "userID"

// CreateTaskInput represents the JSON payload for creating a task.
type CreateTaskInput struct {
	Prompt string `json:"prompt"`
}

// OpenAITaskResponse represents the JSON output from OpenAI.
type OpenAITaskResponse struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

// RegisterInput represents the payload for registering a user.
type RegisterInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginInput represents the payload for logging in a user.
type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	// Open a SQLite database (data.db file will be created in the project folder)
	client, err := ent.Open("sqlite3", "file:data.db?cache=shared&_fk=1")
	if err != nil {
		log.Fatalf("failed opening connection to sqlite: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	// Auto-migrate your schema
	if err := client.Schema.Create(ctx); err != nil {
		log.Fatalf("failed creating schema resources: %v", err)
	}

	// Set up Gorilla Mux router.
	router := mux.NewRouter()

	// Public endpoints.
	router.HandleFunc("/register", registerHandler(client)).Methods("POST")
	router.HandleFunc("/login", loginHandler(client)).Methods("POST")

	// Protected endpoints (use JWT middleware).
	router.Handle("/tasks", verifyTokenMiddleware(http.HandlerFunc(createTaskHandler(client)))).Methods("POST")
	router.Handle("/tasks", verifyTokenMiddleware(http.HandlerFunc(getTasksHandler(client)))).Methods("GET")

	fmt.Println("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

// Middleware: verifyTokenMiddleware validates the JWT and adds the user ID to the context.
func verifyTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect header: "Authorization: Bearer <token>"
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
			// Validate the signing method
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
		// Extract user_id from token claims.
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			http.Error(w, "Invalid user id in token", http.StatusUnauthorized)
			return
		}
		userID := int(userIDFloat)
		// Add userID to the request context.
		ctx := context.WithValue(r.Context(), userCtxKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// registerHandler registers a new user.
func registerHandler(client *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input RegisterInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
		// Hash the password.
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

// loginHandler logs in a user and returns a JWT token.
func loginHandler(client *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input LoginInput
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
		// Compare password.
		if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(input.Password)); err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		// Create JWT token.
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

// createTaskHandler creates a new task (calls OpenAI to generate task details) and associates it with the authenticated user.
func createTaskHandler(client *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input CreateTaskInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
		// Get the authenticated user ID from the context.
		userID, ok := r.Context().Value(userCtxKey).(int)
		if !ok {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}
		// Call OpenAI API to generate task details.
		title, description, err := generateTaskFromPrompt(input.Prompt)
		if err != nil {
			http.Error(w, "Failed to generate task details", http.StatusInternalServerError)
			return
		}
		ctx := context.Background()
		// Retrieve the user entity.
		u, err := client.User.Get(ctx, userID)
		if err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}
		// Create a new task associated with the user.
		t, err := client.Task.
			Create().
			SetTitle(title).
			SetDescription(description).
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

// getTasksHandler retrieves all tasks for the authenticated user.
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

// generateTaskFromPrompt calls the OpenAI API to generate a title and description for a task.
func generateTaskFromPrompt(prompt string) (string, string, error) {
	// If USE_FAKE_AI is set to "true", return dummy data for testing.

	return "Fake Task Title", "This is a fake task description based on the prompt: " + prompt, nil

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		return "", "", fmt.Errorf("OPENAI_API_KEY not set")
	}
	aiClient := openai.NewClient(apiKey)
	ctx := context.Background()
	req := openai.ChatCompletionRequest{
		Model: openai.GPT3Dot5Turbo,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    "system",
				Content: "You are an assistant that generates a JSON object with a title and a detailed description for a todo task. Your output must be valid JSON in the following format: {\"title\": \"Task Title\", \"description\": \"Task Description\"}",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}
	resp, err := aiClient.CreateChatCompletion(ctx, req)
	if err != nil {
		return "", "", err
	}
	responseText := resp.Choices[0].Message.Content
	var result OpenAITaskResponse
	if err := json.Unmarshal([]byte(responseText), &result); err != nil {
		return "", "", fmt.Errorf("failed to parse response: %v", err)
	}
	return result.Title, result.Description, nil
}

# Go Task API

A simple Go-based REST API for managing tasks, built using the `ent` framework and SQLite for database management.

## Features

- Create a new task with a title and content.
- Retrieve a list of all tasks.
- Lightweight and easy to set up.

## Technologies Used

- **Go**: The core programming language.
- **Ent**: An entity framework for Go to interact with the database.
- **SQLite**: A lightweight, file-based database.
- **Gorilla Mux**: A powerful HTTP router and URL matcher.
- **CORS**: Middleware for handling Cross-Origin Resource Sharing.

## Setup

### Prerequisites

- Go 1.20 or higher installed.
- SQLite3 installed.


### API Endpoints
Create a Task
Endpoint: POST /tasks

Request Body:

json
Copy
{
  "title": "First task",
  "content": "This is the content of the task."
}
Response:

json
Copy
{
  "id": 1,
  "title": "First task",
  "content": "This is the content of the task."
}
Get All Tasks
Endpoint: GET /tasks

Response:

json
Copy
[
  {
    "id": 1,
    "title": "First task",
    "content": "This is the content of the task."
  }
]

Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

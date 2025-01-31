package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// User holds the schema definition for the User entity.
type Task struct {
	ent.Schema
}

// Fields of the User.
func (Task) Fields() []ent.Field {
	return []ent.Field{
		field.String("title").Default("unknown"),
		field.String("content").Default("empty"),
	}
}

// Edges of the User.
func (Task) Edges() []ent.Edge {
	return nil
}

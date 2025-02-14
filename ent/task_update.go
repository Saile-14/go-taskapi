// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"go-taskapi/ent/predicate"
	"go-taskapi/ent/task"
	"go-taskapi/ent/user"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/dialect/sql/sqljson"
	"entgo.io/ent/schema/field"
)

// TaskUpdate is the builder for updating Task entities.
type TaskUpdate struct {
	config
	hooks    []Hook
	mutation *TaskMutation
}

// Where appends a list predicates to the TaskUpdate builder.
func (tu *TaskUpdate) Where(ps ...predicate.Task) *TaskUpdate {
	tu.mutation.Where(ps...)
	return tu
}

// SetTitle sets the "title" field.
func (tu *TaskUpdate) SetTitle(s string) *TaskUpdate {
	tu.mutation.SetTitle(s)
	return tu
}

// SetNillableTitle sets the "title" field if the given value is not nil.
func (tu *TaskUpdate) SetNillableTitle(s *string) *TaskUpdate {
	if s != nil {
		tu.SetTitle(*s)
	}
	return tu
}

// SetDescription sets the "description" field.
func (tu *TaskUpdate) SetDescription(s string) *TaskUpdate {
	tu.mutation.SetDescription(s)
	return tu
}

// SetNillableDescription sets the "description" field if the given value is not nil.
func (tu *TaskUpdate) SetNillableDescription(s *string) *TaskUpdate {
	if s != nil {
		tu.SetDescription(*s)
	}
	return tu
}

// SetChecked sets the "checked" field.
func (tu *TaskUpdate) SetChecked(b bool) *TaskUpdate {
	tu.mutation.SetChecked(b)
	return tu
}

// SetNillableChecked sets the "checked" field if the given value is not nil.
func (tu *TaskUpdate) SetNillableChecked(b *bool) *TaskUpdate {
	if b != nil {
		tu.SetChecked(*b)
	}
	return tu
}

// SetSteps sets the "steps" field.
func (tu *TaskUpdate) SetSteps(s []string) *TaskUpdate {
	tu.mutation.SetSteps(s)
	return tu
}

// AppendSteps appends s to the "steps" field.
func (tu *TaskUpdate) AppendSteps(s []string) *TaskUpdate {
	tu.mutation.AppendSteps(s)
	return tu
}

// SetUserID sets the "user" edge to the User entity by ID.
func (tu *TaskUpdate) SetUserID(id int) *TaskUpdate {
	tu.mutation.SetUserID(id)
	return tu
}

// SetNillableUserID sets the "user" edge to the User entity by ID if the given value is not nil.
func (tu *TaskUpdate) SetNillableUserID(id *int) *TaskUpdate {
	if id != nil {
		tu = tu.SetUserID(*id)
	}
	return tu
}

// SetUser sets the "user" edge to the User entity.
func (tu *TaskUpdate) SetUser(u *User) *TaskUpdate {
	return tu.SetUserID(u.ID)
}

// Mutation returns the TaskMutation object of the builder.
func (tu *TaskUpdate) Mutation() *TaskMutation {
	return tu.mutation
}

// ClearUser clears the "user" edge to the User entity.
func (tu *TaskUpdate) ClearUser() *TaskUpdate {
	tu.mutation.ClearUser()
	return tu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (tu *TaskUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, tu.sqlSave, tu.mutation, tu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (tu *TaskUpdate) SaveX(ctx context.Context) int {
	affected, err := tu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (tu *TaskUpdate) Exec(ctx context.Context) error {
	_, err := tu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tu *TaskUpdate) ExecX(ctx context.Context) {
	if err := tu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (tu *TaskUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(task.Table, task.Columns, sqlgraph.NewFieldSpec(task.FieldID, field.TypeInt))
	if ps := tu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := tu.mutation.Title(); ok {
		_spec.SetField(task.FieldTitle, field.TypeString, value)
	}
	if value, ok := tu.mutation.Description(); ok {
		_spec.SetField(task.FieldDescription, field.TypeString, value)
	}
	if value, ok := tu.mutation.Checked(); ok {
		_spec.SetField(task.FieldChecked, field.TypeBool, value)
	}
	if value, ok := tu.mutation.Steps(); ok {
		_spec.SetField(task.FieldSteps, field.TypeJSON, value)
	}
	if value, ok := tu.mutation.AppendedSteps(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, task.FieldSteps, value)
		})
	}
	if tu.mutation.UserCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   task.UserTable,
			Columns: []string{task.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tu.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   task.UserTable,
			Columns: []string{task.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, tu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{task.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	tu.mutation.done = true
	return n, nil
}

// TaskUpdateOne is the builder for updating a single Task entity.
type TaskUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *TaskMutation
}

// SetTitle sets the "title" field.
func (tuo *TaskUpdateOne) SetTitle(s string) *TaskUpdateOne {
	tuo.mutation.SetTitle(s)
	return tuo
}

// SetNillableTitle sets the "title" field if the given value is not nil.
func (tuo *TaskUpdateOne) SetNillableTitle(s *string) *TaskUpdateOne {
	if s != nil {
		tuo.SetTitle(*s)
	}
	return tuo
}

// SetDescription sets the "description" field.
func (tuo *TaskUpdateOne) SetDescription(s string) *TaskUpdateOne {
	tuo.mutation.SetDescription(s)
	return tuo
}

// SetNillableDescription sets the "description" field if the given value is not nil.
func (tuo *TaskUpdateOne) SetNillableDescription(s *string) *TaskUpdateOne {
	if s != nil {
		tuo.SetDescription(*s)
	}
	return tuo
}

// SetChecked sets the "checked" field.
func (tuo *TaskUpdateOne) SetChecked(b bool) *TaskUpdateOne {
	tuo.mutation.SetChecked(b)
	return tuo
}

// SetNillableChecked sets the "checked" field if the given value is not nil.
func (tuo *TaskUpdateOne) SetNillableChecked(b *bool) *TaskUpdateOne {
	if b != nil {
		tuo.SetChecked(*b)
	}
	return tuo
}

// SetSteps sets the "steps" field.
func (tuo *TaskUpdateOne) SetSteps(s []string) *TaskUpdateOne {
	tuo.mutation.SetSteps(s)
	return tuo
}

// AppendSteps appends s to the "steps" field.
func (tuo *TaskUpdateOne) AppendSteps(s []string) *TaskUpdateOne {
	tuo.mutation.AppendSteps(s)
	return tuo
}

// SetUserID sets the "user" edge to the User entity by ID.
func (tuo *TaskUpdateOne) SetUserID(id int) *TaskUpdateOne {
	tuo.mutation.SetUserID(id)
	return tuo
}

// SetNillableUserID sets the "user" edge to the User entity by ID if the given value is not nil.
func (tuo *TaskUpdateOne) SetNillableUserID(id *int) *TaskUpdateOne {
	if id != nil {
		tuo = tuo.SetUserID(*id)
	}
	return tuo
}

// SetUser sets the "user" edge to the User entity.
func (tuo *TaskUpdateOne) SetUser(u *User) *TaskUpdateOne {
	return tuo.SetUserID(u.ID)
}

// Mutation returns the TaskMutation object of the builder.
func (tuo *TaskUpdateOne) Mutation() *TaskMutation {
	return tuo.mutation
}

// ClearUser clears the "user" edge to the User entity.
func (tuo *TaskUpdateOne) ClearUser() *TaskUpdateOne {
	tuo.mutation.ClearUser()
	return tuo
}

// Where appends a list predicates to the TaskUpdate builder.
func (tuo *TaskUpdateOne) Where(ps ...predicate.Task) *TaskUpdateOne {
	tuo.mutation.Where(ps...)
	return tuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (tuo *TaskUpdateOne) Select(field string, fields ...string) *TaskUpdateOne {
	tuo.fields = append([]string{field}, fields...)
	return tuo
}

// Save executes the query and returns the updated Task entity.
func (tuo *TaskUpdateOne) Save(ctx context.Context) (*Task, error) {
	return withHooks(ctx, tuo.sqlSave, tuo.mutation, tuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (tuo *TaskUpdateOne) SaveX(ctx context.Context) *Task {
	node, err := tuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (tuo *TaskUpdateOne) Exec(ctx context.Context) error {
	_, err := tuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tuo *TaskUpdateOne) ExecX(ctx context.Context) {
	if err := tuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (tuo *TaskUpdateOne) sqlSave(ctx context.Context) (_node *Task, err error) {
	_spec := sqlgraph.NewUpdateSpec(task.Table, task.Columns, sqlgraph.NewFieldSpec(task.FieldID, field.TypeInt))
	id, ok := tuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Task.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := tuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, task.FieldID)
		for _, f := range fields {
			if !task.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != task.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := tuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := tuo.mutation.Title(); ok {
		_spec.SetField(task.FieldTitle, field.TypeString, value)
	}
	if value, ok := tuo.mutation.Description(); ok {
		_spec.SetField(task.FieldDescription, field.TypeString, value)
	}
	if value, ok := tuo.mutation.Checked(); ok {
		_spec.SetField(task.FieldChecked, field.TypeBool, value)
	}
	if value, ok := tuo.mutation.Steps(); ok {
		_spec.SetField(task.FieldSteps, field.TypeJSON, value)
	}
	if value, ok := tuo.mutation.AppendedSteps(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, task.FieldSteps, value)
		})
	}
	if tuo.mutation.UserCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   task.UserTable,
			Columns: []string{task.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tuo.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   task.UserTable,
			Columns: []string{task.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &Task{config: tuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, tuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{task.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	tuo.mutation.done = true
	return _node, nil
}

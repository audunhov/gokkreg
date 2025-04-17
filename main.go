package main

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/audunhov/gokkreg/internal"
	"github.com/audunhov/gokkreg/views"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type API struct {
	*internal.Queries
}

func pathToInt32(r *http.Request, key string) (int32, error) {
	strId := r.PathValue(key)
	id, err := strconv.ParseInt(strId, 10, 32)
	return int32(id), err
}

func main() {

	ctx := context.Background()
	db, err := pgx.Connect(ctx, "postgresql://postgres:postgres@db/postgres")
	if err != nil {
		log.Fatal("Could not connect to db:", err)
	}
	defer db.Close(ctx)

	api := API{internal.New(db)}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		users, err := api.ListUsers(r.Context())
		if err != nil {
			http.Error(w, "Could not list users", 500)
		}
		views.HomePage(users).Render(r.Context(), w)
	})

	mux.HandleFunc("/ny/", func(w http.ResponseWriter, r *http.Request) {
		views.RegisterPage().Render(r.Context(), w)
	})

	mux.HandleFunc("/medlem/{id}/", func(w http.ResponseWriter, r *http.Request) {
		id, err := pathToInt32(r, "id")
		if err != nil {
			http.Error(w, ":(", 500)
		}
		user, err := api.GetUserById(r.Context(), id)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
		}
		views.MemberPage(user).Render(r.Context(), w)

	})

	mux.HandleFunc("/role/", func(w http.ResponseWriter, r *http.Request) {
		roles, err := api.ListRoles(r.Context())
		if err != nil {
			http.Error(w, "No roles found", 404)
			return
		}
		role_types, err := api.ListRoleTypes(r.Context())
		if err != nil {
			http.Error(w, "No roles found", 404)
			return
		}
		users, err := api.ListUsers(r.Context())
		if err != nil {
			http.Error(w, "No roles found", 404)
			return
		}
		views.RolesPage(roles, role_types, users).Render(r.Context(), w)

	})
	mux.HandleFunc("/role_type/", func(w http.ResponseWriter, r *http.Request) {

		role_types, err := api.ListRoleTypes(r.Context())
		if err != nil {
			http.Error(w, "Something wrong", 500)
			return
		}

		levels := internal.AllLevelValues()
		views.RoleTypesPage(role_types, levels).Render(r.Context(), w)

	})

	mux.HandleFunc("/role/{id}/", func(w http.ResponseWriter, r *http.Request) {
		id, err := pathToInt32(r, "id")
		if err != nil {
			http.Error(w, ":(", 500)
		}
		role, err := api.GetRoleById(r.Context(), id)
		if err != nil {
			http.Error(w, "Role not found", http.StatusNotFound)
		}
		user, err := api.GetUserById(r.Context(), role.Userid)
		if err != nil {
			http.Error(w, "Role not found", http.StatusNotFound)
		}
		roleType, err := api.GetRoleTypeById(r.Context(), role.Roletypeid)
		if err != nil {
			http.Error(w, "Role not found", http.StatusNotFound)
		}
		views.RolePage(user, role, roleType).Render(r.Context(), w)

	})

	v1 := http.NewServeMux()
	v1.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hei fra API"))
	})

	v1.HandleFunc("GET /user/", func(w http.ResponseWriter, r *http.Request) {
		users, err := api.ListUsers(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		json.NewEncoder(w).Encode(users)
	})

	v1.HandleFunc("POST /user/", func(w http.ResponseWriter, r *http.Request) {

		name := r.FormValue("name")
		email := r.FormValue("email")
		phone := r.FormValue("phone")
		bday := r.FormValue("birthdate")

		bdaytime, err := time.Parse("2006-01-02", bday)
		user, err := api.InsertUser(r.Context(), internal.InsertUserParams{
			Name:     name,
			Email:    pgtype.Text{String: email, Valid: email != ""},
			Phone:    pgtype.Text{String: phone, Valid: phone != ""},
			Birthday: pgtype.Date{Time: bdaytime, Valid: err == nil},
		})
		if err != nil {
			http.Error(w, "Could not create user: "+err.Error(), 500) // TODO: Better status
			return
		}
		json.NewEncoder(w).Encode(user)
	})

	v1.HandleFunc("DELETE /user/{id}/", func(w http.ResponseWriter, r *http.Request) {
		id, err := pathToInt32(r, "id")
		if err != nil {
			http.Error(w, "Path must contain int id", http.StatusBadRequest)
			return
		}

		err = api.DeleteUser(r.Context(), int32(id))
		if err != nil {
			http.Error(w, "Could not delete user", 500) // TODO: Better status
		}
		w.Write([]byte("Deleted!"))
	})

	v1.HandleFunc("GET /role_type/", func(w http.ResponseWriter, r *http.Request) {
		role_types, err := api.ListRoleTypes(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		json.NewEncoder(w).Encode(role_types)
	})

	v1.HandleFunc("POST /role_type/", func(w http.ResponseWriter, r *http.Request) {
		title := r.FormValue("title")
		access := r.FormValue("access")

		level := internal.Level(access)

		if !level.Valid() {
			http.Error(w, "Invalid access level", 400)
			return
		}

		roleType, err := api.InsertRoleType(r.Context(), internal.InsertRoleTypeParams{
			Title:       title,
			Accesslevel: level,
		})
		if err != nil {
			http.Error(w, "Could not create role type", 500) // TODO: Better status
		}
		json.NewEncoder(w).Encode(roleType)
	})

	v1.HandleFunc("DELETE /role_type/{id}/", func(w http.ResponseWriter, r *http.Request) {
		id, err := pathToInt32(r, "id")
		if err != nil {
			http.Error(w, "Path must contain int id", http.StatusBadRequest)
			return
		}

		err = api.DeleteRoleType(r.Context(), int32(id))
		if err != nil {
			http.Error(w, "Could not delete role type", 500) // TODO: Better status
		}
		w.Write([]byte("Deleted!"))
	})

	v1.HandleFunc("GET /role/", func(w http.ResponseWriter, r *http.Request) {
		roles, err := api.ListRoles(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		json.NewEncoder(w).Encode(roles)
	})

	v1.HandleFunc("POST /role/", func(w http.ResponseWriter, r *http.Request) {

		suid := r.FormValue("user")
		srt := r.FormValue("role_type")

		uid, err := strconv.ParseInt(suid, 10, 32)

		if err != nil {
			http.Error(w, "invalid user id", 400)
			return
		}

		rt, err := strconv.ParseInt(srt, 10, 32)
		if err != nil {
			http.Error(w, "invalid role type id", 400)
			return
		}

		role, err := api.InsertRole(r.Context(), internal.InsertRoleParams{
			Userid:     int32(uid),
			Roletypeid: int32(rt),
		})
		if err != nil {
			http.Error(w, "Could not create role", 500) // TODO: Better status
		}
		json.NewEncoder(w).Encode(role)
	})

	v1.HandleFunc("DELETE /role/{id}/", func(w http.ResponseWriter, r *http.Request) {
		id, err := pathToInt32(r, "id")
		if err != nil {
			http.Error(w, "Path must contain int id", http.StatusBadRequest)
			return
		}

		err = api.DeleteRole(r.Context(), int32(id))
		if err != nil {
			http.Error(w, "Could not delete role", 500) // TODO: Better status
		}
		w.Write([]byte("Deleted!"))
	})

	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", v1))

	port := ":8070"
	slog.Info("Server running at " + port)
	if err := http.ListenAndServe(port, mux); err != nil {
		slog.Error("Fatal error", "err", err)
	}
}

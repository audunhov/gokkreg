package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/audunhov/gokkreg/internal"
	"github.com/audunhov/gokkreg/views"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

type API struct {
	*internal.Queries
}

func pathToInt32(r *http.Request, key string) (int32, error) {
	strId := r.PathValue(key)
	id, err := strconv.ParseInt(strId, 10, 32)
	return int32(id), err
}
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
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

		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login/", http.StatusTemporaryRedirect)
			return
		}

		var uuid pgtype.UUID
		err = uuid.Scan(cookie.Value)
		uuid.Valid = err == nil

		session, err := api.GetSessionById(r.Context(), uuid)
		if err != nil {
			http.Redirect(w, r, "/login/", http.StatusTemporaryRedirect)
			return
		}
		user, err := api.GetUserById(r.Context(), session.Userid)
		if err != nil {
			http.Redirect(w, r, "/login/", http.StatusTemporaryRedirect)
			return
		}
		stats, err := api.GetUserStats(r.Context())
		if err != nil {
			http.Error(w, "Can't load stats", 500)
			return
		}

		views.DashboardPage(stats.CurrentCount, stats.CountAMonthAgo, user).Render(r.Context(), w)
	})
	mux.HandleFunc("/members/", func(w http.ResponseWriter, r *http.Request) {
		users, err := api.ListUsers(r.Context())
		if err != nil {
			http.Error(w, "Could not list users", 500)
			return
		}
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login/", http.StatusUnauthorized)
			return
		}

		var uuid pgtype.UUID
		err = uuid.Scan(cookie.Value)
		uuid.Valid = err == nil

		session, err := api.GetSessionById(r.Context(), uuid)
		user, err := api.GetUserById(r.Context(), session.Userid)

		views.HomePage(users, user).Render(r.Context(), w)
	})

	mux.HandleFunc("/ny/", func(w http.ResponseWriter, r *http.Request) {
		views.RegisterPage().Render(r.Context(), w)
	})

	mux.HandleFunc("/login/", func(w http.ResponseWriter, r *http.Request) {

		session, err := r.Cookie("session_id")
		if err == nil {
			var uuid pgtype.UUID
			err := uuid.Scan(session.Value)
			uuid.Valid = err == nil

			_, err = api.GetSessionById(r.Context(), uuid)
			if err == nil {
				api.SetSessionLastActive(r.Context(), uuid)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}

		}

		views.LoginPage().Render(r.Context(), w)
	})

	mux.HandleFunc("/logout/", func(w http.ResponseWriter, r *http.Request) {

		session, err := r.Cookie("session_id")
		if err == nil {

			var uuid pgtype.UUID
			err := uuid.Scan(session.Value)
			uuid.Valid = err == nil
			api.InvalidateSession(r.Context(), uuid)
		}

		views.LogoutPage().Render(r.Context(), w)
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
		roles, rerr := api.ListRoles(r.Context())
		role_types, rterr := api.ListRoleTypes(r.Context())
		users, uerr := api.ListUsers(r.Context())
		err := errors.Join(rerr, rterr, uerr)
		if err != nil {
			http.Error(w, "Could not load errors:"+err.Error(), 404)
			return
		}
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login/", http.StatusUnauthorized)
			return
		}

		var uuid pgtype.UUID
		err = uuid.Scan(cookie.Value)
		uuid.Valid = err == nil

		session, err := api.GetSessionById(r.Context(), uuid)
		user, err := api.GetUserById(r.Context(), session.Userid)

		views.RolesPage(roles, role_types, users, user).Render(r.Context(), w)

	})
	mux.HandleFunc("/role_type/", func(w http.ResponseWriter, r *http.Request) {

		role_types, err := api.ListRoleTypes(r.Context())
		if err != nil {
			http.Error(w, "Something wrong", 500)
			return
		}
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login/", http.StatusUnauthorized)
			return
		}

		var uuid pgtype.UUID
		err = uuid.Scan(cookie.Value)
		uuid.Valid = err == nil

		session, err := api.GetSessionById(r.Context(), uuid)
		user, err := api.GetUserById(r.Context(), session.Userid)

		levels := internal.AllLevelValues()
		views.RoleTypesPage(role_types, levels, user).Render(r.Context(), w)

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

	v1.HandleFunc("POST /login/", func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")
		password := r.FormValue("password")
		user, err := api.GetUserByEmail(r.Context(), email)

		if err != nil {
			http.Error(w, "No user found with that email/password combination", 404)
			return
		}

		valid := CheckPasswordHash(password, user.Password.String)

		if !valid {
			http.Error(w, "No user found with that email/password combination", 404)
			return
		}

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Something extremely wrong has happened", 500)
			return
		}

		addr, err := netip.ParseAddr(host)
		if err != nil {
			http.Error(w, "Something extremely wrong has happened", 500)
			return
		}

		ua := r.UserAgent()

		expires := time.Now().Add(14 * 24 * time.Hour)

		session, err := api.NewSession(r.Context(), internal.NewSessionParams{
			Userid:    user.ID,
			Expiresat: pgtype.Timestamptz{Time: expires, Valid: true},
			Ipaddress: &addr,
			Useragent: pgtype.Text{String: ua, Valid: ua != ""},
		})

		if err != nil {
			http.Error(w, "Could not create session, try again: "+err.Error(), 500)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    session.ID.String(),
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(expires.Sub(time.Now()).Seconds()),
		})
		w.Header().Set("HX-Redirect", "/")
	})

	v1.HandleFunc("POST /newpass/{id}/", func(w http.ResponseWriter, r *http.Request) {
		id, err := pathToInt32(r, "id")
		if err != nil {
			http.Error(w, "Invalid path id", 400)
			return
		}
		pass := r.FormValue("password")

		hashed, err := HashPassword(pass)
		user, err := api.UpdateUserPass(r.Context(), internal.UpdateUserPassParams{ID: id, Password: pgtype.Text{
			String: hashed,
			Valid:  err == nil,
		}})

		if err != nil {
			http.Error(w, "Could not update password", 500)
		}

		json.NewEncoder(w).Encode(user)

	})

	v1.HandleFunc("POST /register/", func(w http.ResponseWriter, r *http.Request) {

		name := r.FormValue("name")
		email := r.FormValue("email")
		phone := r.FormValue("phone")
		bday := r.FormValue("birthday")

		bdaytime, err := time.Parse("2006-01-02", bday)
		user, err := api.InsertUser(r.Context(), internal.InsertUserParams{
			Name:     name,
			Email:    email,
			Phone:    pgtype.Text{String: phone, Valid: phone != ""},
			Birthday: pgtype.Date{Time: bdaytime, Valid: err == nil},
		})
		if err != nil {
			http.Error(w, "Could not create user: "+err.Error(), 500) // TODO: Better status
			return
		}
		w.Header().Set("HX-Redirect", fmt.Sprintf("/medlem/%d/", user.ID))
		json.NewEncoder(w).Encode(user)

	})

	v1.HandleFunc("POST /user/", func(w http.ResponseWriter, r *http.Request) {

		name := r.FormValue("name")
		email := r.FormValue("email")
		phone := r.FormValue("phone")
		bday := r.FormValue("birthdate")

		bdaytime, err := time.Parse("2006-01-02", bday)
		user, err := api.InsertUser(r.Context(), internal.InsertUserParams{
			Name:     name,
			Email:    email,
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

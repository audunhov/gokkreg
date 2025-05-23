// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package internal

import (
	"database/sql/driver"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"
)

type Level string

const (
	LevelRead  Level = "read"
	LevelWrite Level = "write"
	LevelAdmin Level = "admin"
)

func (e *Level) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = Level(s)
	case string:
		*e = Level(s)
	default:
		return fmt.Errorf("unsupported scan type for Level: %T", src)
	}
	return nil
}

type NullLevel struct {
	Level Level
	Valid bool // Valid is true if Level is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullLevel) Scan(value interface{}) error {
	if value == nil {
		ns.Level, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.Level.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullLevel) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.Level), nil
}

func (e Level) Valid() bool {
	switch e {
	case LevelRead,
		LevelWrite,
		LevelAdmin:
		return true
	}
	return false
}

func AllLevelValues() []Level {
	return []Level{
		LevelRead,
		LevelWrite,
		LevelAdmin,
	}
}

type Role struct {
	ID         int32
	Userid     int32
	Roletypeid int32
	Createdat  pgtype.Timestamptz
	Finishedat pgtype.Timestamptz
}

type RoleType struct {
	ID          int32
	Title       string
	Createdat   pgtype.Timestamptz
	Accesslevel Level
}

type Session struct {
	ID         pgtype.UUID
	Userid     int32
	Createdat  pgtype.Timestamptz
	Lastseenat pgtype.Timestamptz
	Expiresat  pgtype.Timestamptz
	Ipaddress  *netip.Addr
	Useragent  pgtype.Text
	Isactive   bool
}

type User struct {
	ID        int32
	Name      string
	Email     string
	Phone     pgtype.Text
	Password  pgtype.Text
	Birthday  pgtype.Date
	Createdat pgtype.Timestamptz
}

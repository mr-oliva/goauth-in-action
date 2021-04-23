// Package db provides features like nosql library
// nosql libraly: https://github.com/petersirka/nosql
package db

type DB interface {
	Insert(data interface{}) error
	Remove(column, key string) error
	Where(column, key string) (map[string]interface{}, error)
}

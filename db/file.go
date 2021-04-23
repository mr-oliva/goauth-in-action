package db

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type File struct {
	Name string
}

func (f *File) Insert(data interface{}) error {
	bytesData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	fp, err := os.OpenFile(f.Name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer fp.Close()
	fp.Write(append(bytesData, []byte("\n")...))
	return nil
}

func (f *File) Remove(column, key string) error {
	fp, err := os.OpenFile(f.Name, os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	var remainData []byte
	for scanner.Scan() {
		var data map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &data); err != nil {
			return err
		}
		for k, v := range data {
			if k == column && v == key {
				continue
			}
		}
		remainData = append(remainData, scanner.Bytes()...)
	}
	fp.Write(remainData)
	return nil
}

func (f *File) Where(column, key string) (map[string]interface{}, error) {
	fp, err := os.OpenFile(f.Name, os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		var data map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &data); err != nil {
			return nil, err
		}
		for k, v := range data {
			if k == column && v == key {
				return data, nil
			}
		}
	}
	return nil, fmt.Errorf("not found to %s in %s", key, column)
}

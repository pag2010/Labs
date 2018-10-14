package main

import (
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
)

var list []sFile

func TestX(t *testing.T) {

	err := ReadFiles("dir2/", "")
	if err != nil {
		t.Error("Невозможно прочитать файлы")
	}
	//fmt.Println(len(list))
	list1 := make([]sFile, len(list))
	copy(list1, list)
	list = make([]sFile, 0)
	err = Extract()
	if err != nil {
		t.Error("Невозможно извлечь файлы")
	}
	err = ReadFiles("extract/", "")
	if err != nil {
		t.Error("Невозможно прочитать файлы")
	}
	//fmt.Println(len(list1))
	for i, f := range list {
		if !((f.Name == list1[i].Name) && (f.Hash == list1[i].Hash)) {
			t.Error("Извлеченные файлы не совпадают с исходными!")
			return
		}
	}

}

func ReadFiles(path string, dir string) error {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	for _, file := range files {
		l := new(sFile)
		l.Name = filepath.Join(dir, file.Name())
		//fmt.Println(l.Name)
		if file.IsDir() {
			err := ReadFiles(filepath.Join(path, file.Name()), filepath.Join(dir, file.Name()))
			if err != nil {
				return err
			}
		} else {
			f, err := ioutil.ReadFile(filepath.Join(path, file.Name()))
			if err != nil {
				return err
			}
			l.Hash = strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(f)))
		}
		list = append(list, *l)
	}
	return nil
}

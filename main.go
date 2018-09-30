// Laba1 project main.go
package main

import (
	"archive/zip"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var Path string
var Output string
var Mode string
var List []string

//var FileNames string

func init() {
	flag.StringVar(&Path, "path", "", "Here you should place Path")
	flag.StringVar(&Output, "out", "done.zip", "Here you should place Name of your zip")
	flag.StringVar(&Mode, "mode", "z", "Here you should place z - to zip, sz - to sertificate zip, u - to unzip")
}

func main() {
	flag.Parse()
	log.Printf(Path)
	output := Output

	switch Mode {
	case "z":
		newZipFile, err := os.Create(output) //создается zip архив
		if err != nil {
			log.Fatal(err)
		}
		defer newZipFile.Close()

		ZipWriter := zip.NewWriter(newZipFile) //создается записыватель в zip
		defer ZipWriter.Close()

		err = ZipFiles(Path, ZipWriter, "")
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Zipped File: " + output)
		p := Path + "\\"
		for _, file := range List {
			file = strings.Replace(file, p, "", -1)
			log.Printf(file)
		}
	default:
		log.Fatal("Unknown code for mode")
	}
}

func ZipFiles(path string, zipWriter *zip.Writer, dirName string) error {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	// Add files to zip
	for _, file := range files {
		log.Printf(file.Name(), file.IsDir())
		if file.IsDir() {
			_, err := zipWriter.Create(dirName + file.Name() + "\\")
			if err != nil {
				return err
			}
			ZipFiles(path+"\\"+file.Name(), zipWriter, dirName+file.Name()+"\\")
		} else {
			List = append(List, path+"\\"+file.Name())
			writer, err := zipWriter.Create(dirName + file.Name())
			if err != nil {
				return err
			}

			data, err := ioutil.ReadFile(path + "\\" + file.Name())
			if err != nil {
				return err
			}
			_, err = writer.Write([]byte(data))
			if err != nil {
				return err
			}

		}
	}
	return nil
}

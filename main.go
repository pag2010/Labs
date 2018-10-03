// Laba1 project main.go
package main

import (
	"archive/zip"
	//	"crypto/rand"
	//"crypto/rsa"
	"bytes"
	//"crypto/sha256"

	"crypto/tls"
	//"crypto/x509"
	"encoding/pem"

	//"crypto"
	//"errors"
	"flag"

	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"pkcs7"
	"strings"
)

type File struct {
	Name string `xml:"name"`
	Size int64  `xml:"size`
}

var Path string
var Output string
var Mode string
var List []File
var Hash string

//var FileNames string

func init() {
	flag.StringVar(&Path, "path", "", "Here you should place Path")
	flag.StringVar(&Output, "out", "out.zip", "Here you should place Name of your zip")
	flag.StringVar(&Mode, "mode", "z", "Here you should place z - to zip, sz - to sertificate zip, u - to unzip")
	flag.StringVar(&Hash, "hash", "", "Here you should place hash")
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
		for i, file := range List {
			//file.cngName(p)
			List[i].cngName(p)
			//file.Name = strings.Replace(file.Name, p, "", -1)
			log.Printf(file.Name)
		}
		CreateMeta(List)
	case "s":
		SignArchive("my.crt", "my.key")
	case "i":
		//Verify("", "")
	default:
		log.Fatal("Unknown code for mode")
	}
}

func (f *File) cngName(path string) {
	f.Name = strings.Replace(f.Name, path, "", -1)
}

func CreateMeta(list []File) error {
	f, err := os.Create("meta.xml")
	if err != nil {
		log.Printf("error: %v\n", err)
		return err
	}
	defer f.Close()

	output, err := xml.MarshalIndent(list, "  ", "    ")
	if err != nil {
		log.Printf("error: %v\n", err)
		return err
	}

	f.Write(output)
	return nil
}

func SignArchive(cert string, pkey string) error {
	zipFile, err := ioutil.ReadFile("./out.zip")
	if err != nil {
		log.Printf("error")
		return err
	}

	signedData, err := pkcs7.NewSignedData(zipFile)
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
		return err
	}

	recpcert, recpkey := tls.LoadX509KeyPair(cert, pkey)
	signedData.AddSigner(recpcert.Leaf, recpkey, pkcs7.SignerInfoConfig{})
	if err != nil {
		log.Printf("error")
		return err
	}

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		log.Printf("error")
		return err
	}
	buf := new(bytes.Buffer)
	pem.Encode(buf, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
	sz, err := os.Create("zip.szp")
	if err != nil {
		log.Printf("error")
		return err
	}
	defer sz.Close()
	data, err := ioutil.ReadFile(Output)
	if err != nil {
		log.Printf("error")
		return err
	}
	sz.Write(buf.Bytes())
	sz.Write(data)
	log.Print("Data signed")
	return nil
}

func ZipFiles(path string, zipWriter *zip.Writer, dirName string) error {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	L := new(File)
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
			L.Name = path + "\\" + file.Name()
			L.Size = file.Size()
			List = append(List, *L)
			if err != nil {
				return err
			}
			log.Printf(path + "\\" + file.Name())
			data, err := os.Open(path + "\\" + file.Name())
			defer data.Close()
			//log.Printf(path + "\\" + file.Name())
			if err != nil {
				return err
			}

			info, err := data.Stat()
			if err != nil {
				return err
			}

			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}

			header.Name = dirName + file.Name()

			header.Method = zip.Deflate

			zwriter, err := zipWriter.CreateHeader(header)
			if err != nil {
				return err
			}
			if _, err = io.Copy(zwriter, data); err != nil {
				return err
			}

		}
	}
	return nil
}

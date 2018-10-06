// Laba1 project main.go
package main

import (
	"archive/zip"
	//	"crypto/rand"
	"bytes"
	"crypto/rsa"

	//"crypto/sha256"
	//"crypto/tls"
	"encoding/base64"

	"crypto/x509"
	"encoding/pem"

	//"crypto"
	//"errors"
	"flag"

	"crypto/sha1"
	"encoding/binary"
	"encoding/xml"
	"fmt"

	//"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
	"pkcs7"
	"strings"
	"time"
)

type File struct {
	Name   string    `xml: "name"`
	Size   int64     `xml: "size"`
	CSize  int64     `xml: "compressed_size"`
	Modify time.Time `xml: "modify"`
	Hash   string    `xml: "hash"`
}

var Path string
var Output string
var Mode string
var List []File
var Hash string
var CertName string
var KeyName string

//var FileNames string

func init() {
	flag.StringVar(&Path, "path", "./", "Here you should place Path")
	flag.StringVar(&Output, "out", "out.zip", "Here you should place Name of your zip")
	flag.StringVar(&Mode, "mode", "z", "Here you should place z - to zip, sz - to sertificate zip, u - to unzip")
	flag.StringVar(&Hash, "hash", "", "Here you should place hash")
	flag.StringVar(&CertName, "cert", "./", "Here you should place path to certificate")
	flag.StringVar(&KeyName, "pkey", "./", "Here you should place path to private key")
}

func main() {
	flag.Parse()
	//log.Printf(Path)
	//output := Output

	switch Mode {
	case "z":
		/*newZipFile, err := os.Create(output) //создается zip архив
		if err != nil {
			log.Fatal(err)
		}
		defer newZipFile.Close()*/

		newZipFile := new(bytes.Buffer)
		ZipWriter := zip.NewWriter(newZipFile) //создается записыватель в zip
		//err = ZipWriter.Close()

		err := ZipFiles(Path, ZipWriter, "")
		err = ZipWriter.Close()
		if err != nil {
			log.Fatal(err)
		}
		z, err := os.Create("Zip.zip")
		defer z.Close()
		z.Write(newZipFile.Bytes())
		log.Println("Files were zipped")
		p := Path + "\\"
		for i, file := range List {
			//file.cngName(p)
			List[i].cngName(p)
			//file.Name = strings.Replace(file.Name, p, "", -1)
			log.Printf(file.Name)
		}
		ZipMetaFile, err := CreateMeta(List, newZipFile)
		m, err := os.Create("Meta.zip")
		defer m.Close()
		if err != nil {
			log.Fatal(err)
		}
		m.Write(ZipMetaFile.Bytes())
		EndZip := new(bytes.Buffer)
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, uint32(ZipMetaFile.Len()))
		EndZip.Write(bs)
		EndZip.Write(ZipMetaFile.Bytes())
		EndZip.Write(newZipFile.Bytes())
		//err = SignZip("my.crt", "my.key", Output, EndZip)
		err = SignZip(CertName, KeyName, Output, EndZip)
		if err != nil {
			log.Fatal(err)
		}

	case "x":

	case "i":
		err := Verify(CertName)
		if err != nil {
			log.Fatal(err)
		}

	default:
		log.Fatal("Unknown code for mode")
	}
}

func (f *File) cngName(path string) {
	f.Name = strings.Replace(f.Name, path, "", -1)
}

func CreateMeta(list []File, zipFile *bytes.Buffer) (*bytes.Buffer, error) {
	/*f, err := os.Create("meta.xml")
	if err != nil {
		log.Printf("error: %v\n", err)
		return err
	}
	defer f.Close()*/

	f := new(bytes.Buffer)
	output, err := xml.MarshalIndent(list, "  ", "    ")
	if err != nil {
		log.Printf("error: %v\n", err)
		return nil, err
	}
	MetaBuf := new(bytes.Buffer)
	zipMetaWriter := zip.NewWriter(MetaBuf)
	//defer zipMetaWriter.Close()
	m, err := zipMetaWriter.Create("meta.xml")
	if err != nil {
		return nil, err
	}
	m.Write(output)
	err = zipMetaWriter.Close()
	if err != nil {
		return nil, err
	}

	f.Write(MetaBuf.Bytes())
	/*zipFile = f
	s, err := os.Create("meta.zip")
	s.Write(f.Bytes())
	defer s.Close()*/
	/*err = zipMetaWriter.Close()
	if err != nil {
		log.Fatal(err)
	}*/

	//f.Write(MetaBuf.Bytes())
	//f.Write(zipFile.Bytes())
	return f, nil
}

func Verify(cert string) error {
	szip, err := ioutil.ReadFile(Output)
	if err != nil {
		log.Printf("Unable to read zip")
		return err
	}
	sign, err := pkcs7.Parse(szip)
	if err != nil {
		log.Printf("Sign is broken!")
		return err
	}
	err = sign.Verify()
	if err != nil {
		log.Printf("Sign is not verified")
	}
	fmt.Println((sign.Certificates[0].Issuer.CommonName))
	return nil
}

func SignZip(cert string, key string, Output string, zipFile *bytes.Buffer) error {
	/*zipFile, err := ioutil.ReadFile(Output)
	if err != nil {
		log.Printf("error")
		return err
	}*/

	signedData, err := pkcs7.NewSignedData(zipFile.Bytes())
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
		return err
	}
	certFile, err := ioutil.ReadFile(cert)

	certBlock, _ := pem.Decode(certFile)
	if certBlock == nil {
		panic("failed to parse certificate PEM")
	}
	recpcert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	pkeyFile, err := ioutil.ReadFile(key)
	if err != nil {
		log.Printf("Can not read private key file")
		return err
	}
	block, _ := pem.Decode(pkeyFile)
	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	var recpkey *rsa.PrivateKey
	recpkey = parseResult.(*rsa.PrivateKey)

	signedData.AddSigner(recpcert, recpkey, pkcs7.SignerInfoConfig{})
	if err != nil {
		log.Printf("error")
		return err
	}

	detachedSignature, err := signedData.Finish()
	if err != nil {
		log.Printf("error")
		return err
	}

	sz, err := os.Create(Output)
	if err != nil {
		log.Printf("error")
		return err
	}
	defer sz.Close()
	/*data, err := ioutil.ReadFile(Output)
	if err != nil {
		log.Printf("error")
		return err
	}*/
	sz.Write(detachedSignature)
	//data = data
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
		//log.Printf(file.Name(), file.IsDir())
		if file.IsDir() {
			_, err := zipWriter.Create(dirName + file.Name() + "\\")
			if err != nil {
				return err
			}
			ZipFiles(path+"\\"+file.Name(), zipWriter, dirName+file.Name()+"\\")
		} else {

			if err != nil {
				return err
			}
			//log.Printf(path + "\\" + file.Name())
			data, err := os.Open(path + "\\" + file.Name())
			defer data.Close()
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
			L.Name = path + "\\" + file.Name()
			L.Size = file.Size()
			L.CSize = int64(header.CompressedSize64)
			L.Modify = header.Modified
			h := sha1.New()
			d, err := ioutil.ReadFile(L.Name)
			if err != nil {
				return err
			}
			h.Write(d)

			L.Hash = base64.URLEncoding.EncodeToString(h.Sum(nil))
			List = append(List, *L)

		}
	}
	/*err = SignZip("my.crt", "my.key", Output, zipFile)
	if err != nil {
		return err
	}*/
	return nil
}

func Extract() error {

	return nil
}

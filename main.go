// Laba1 project main.go
package main

import (
	"archive/zip"
	//	"crypto/rand"
	"bytes"
	"crypto/rsa"
	"path/filepath"

	//"crypto/sha256"
	//"crypto/tls"
	"encoding/base64"

	"crypto/x509"
	"encoding/pem"

	//"crypto"
	"errors"
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

	//"strings"
	"time"
)

type sFile struct {
	Name   string    `xml: "name"`
	Size   int64     `xml: "size"`
	CSize  int64     `xml: "compressed_size"`
	Modify time.Time `xml: "modify"`
	Hash   string    `xml: "hash"`
}
type meta struct {
	File []sFile `xml: "file"`
}

var Path string
var Output string
var Mode string
var List []sFile
var Hash string
var CertName string
var KeyName string

func init() {
	flag.StringVar(&Path, "path", "./", "Here you should place Path")
	flag.StringVar(&Output, "out", "out.zip", "Here you should place Name of your zip")
	flag.StringVar(&Mode, "mode", "", "Here you should place z - to zip, sz - to sertificate zip, u - to unzip")
	flag.StringVar(&Hash, "hash", "", "Here you should place hash")
	flag.StringVar(&CertName, "cert", "./", "Here you should place path to certificate")
	flag.StringVar(&KeyName, "pkey", "./", "Here you should place path to private key")
}

func main() {
	flag.Parse()

	switch Mode {
	case "z":

		newZipFile := new(bytes.Buffer)
		ZipWriter := zip.NewWriter(newZipFile) //создается записыватель в zip

		err := ZipFiles(Path, ZipWriter, "")
		err = ZipWriter.Close()
		if err != nil {
			log.Printf(err.Error())
			return
		}

		log.Println("Files were zipped")
		p := Path + "\\"
		for i, file := range List {

			err := List[i].cngName(p)

			if err != nil {
				log.Printf(err.Error())
				return
			} else {
				log.Printf(file.Name)
			}
		}
		ZipMetaFile, err := CreateMeta(List, newZipFile)

		EndZip := new(bytes.Buffer)
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, uint32(ZipMetaFile.Len()))

		EndZip.Write(bs)
		EndZip.Write(ZipMetaFile.Bytes())
		EndZip.Write(newZipFile.Bytes())

		err = SignZip(CertName, KeyName, Output, EndZip)
		if err != nil {
			log.Printf(err.Error())
			return
		}

	case "x":
		err := Extract()
		if err != nil {
			log.Printf(err.Error())
			return
		}

	case "i":
		err := Verify(CertName)
		if err != nil {
			log.Printf(err.Error())
			return
		}

	default:
		log.Printf("Unknown key for mode")
		return
	}
}

//метод нужен для удаления из полного имени файла ненужной части пути,
//например у имени: "С:\Sasha\dirToZip\Laba.go" часть "С:\Sasha\" не нужна после создания архива
func (f *sFile) cngName(path string) error {
	var err error
	f.Name, err = filepath.Rel(path, f.Name)
	return err
}

func CreateMeta(list []sFile, zipFile *bytes.Buffer) (*bytes.Buffer, error) {

	var l meta
	l.File = list
	output, err := xml.MarshalIndent(l, "  ", "    ")
	if err != nil {
		log.Printf("error: %v\n", err)
		return nil, err
	}
	MetaBuf := new(bytes.Buffer)
	zipMetaWriter := zip.NewWriter(MetaBuf)

	m, err := zipMetaWriter.Create("meta.xml")
	if err != nil {
		return nil, err
	}
	m.Write(output)
	err = zipMetaWriter.Close()
	if err != nil {
		return nil, err
	}

	return MetaBuf, nil
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
		return err
	}
	fmt.Println("Sign was made by " + sign.Certificates[0].Issuer.CommonName)
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
		log.Printf("failed to parse certificate PEM")
		return errors.New("failed to parse certificate PEM")
	}
	recpcert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Printf("failed to parse certificate: " + err.Error())
		return err
	}
	pkeyFile, err := ioutil.ReadFile(key)
	if err != nil {
		log.Printf("Can not read private key file")
		return err
	}
	block, _ := pem.Decode(pkeyFile)
	if block == nil {
		log.Printf("failed to parse private key PEM")
		return errors.New("failed to parse private key PEM")
	}
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
	defer sz.Close()
	if err != nil {
		log.Printf("error")
		return err
	}

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
	L := new(sFile)
	// Add files to zip
	for _, file := range files {
		//log.Printf(file.Name(), file.IsDir())
		if file.IsDir() {
			_, err := zipWriter.Create(filepath.Join(dirName, file.Name()) + "/")
			if err != nil {
				return err
			}
			/*			log.Printf(filepath.Join(dirName, file.Name()))*/
			//ZipFiles(path+"\\"+file.Name(), zipWriter, dirName+file.Name()+"\\")
			ZipFiles(filepath.Join(path, file.Name()), zipWriter, filepath.Join(dirName, file.Name()))
		} else {

			/*if err != nil {
				return err
			}
			log.Printf(filepath.Join(path, file.Name()))*/
			//data, err := os.Open(path + "\\" + file.Name())
			data, err := os.Open(filepath.Join(path, file.Name()))
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

			header.Name = filepath.Join(dirName, file.Name())

			header.Method = zip.Deflate

			zwriter, err := zipWriter.CreateHeader(header)
			if err != nil {
				return err
			}
			if _, err = io.Copy(zwriter, data); err != nil {
				return err

			}
			L.Name = filepath.Join(path, file.Name())
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
	err := Verify(CertName)
	data, err := ioutil.ReadFile(Output)
	if err != nil {
		log.Printf("unable to read szp")
		return err
	}

	sign, err := pkcs7.Parse(data)
	if err != nil {
		log.Printf("Sign is broken!")
		return err
	}

	data = sign.Content //получаю содержимое архива без подписи

	mlen := binary.LittleEndian.Uint32(data[:4]) //получаю длину метаданных

	bmeta := data[4 : mlen+4] //получаю байты метаданных
	/*zmeta, err := os.Create("umeta.zip") //создаю архив только метаданных
	defer zmeta.Close()
	zmeta.Write(bmeta)*/

	dzip := data[mlen+4:] // считываю остальную часть архива с файлами
	/*zm, err := os.Create("uzip.zip")
	defer zm.Close()
	zm.Write(dzip) //записываю их в файл для разорхивации
	if err != nil {
		log.Printf("unable to read meta lenght")
		return err
	}*/

	//m, err := zip.OpenReader("umeta.zip")
	m, err := zip.NewReader(bytes.NewReader(bmeta), int64(len(bmeta)))
	if err != nil {
		log.Printf("Can not open meta")
		return err
	}

	f := m.File[0] //т.к. в архиве меты всего 1 файл, получаю его
	buf := new(bytes.Buffer)

	st, err := f.Open()
	if err != nil {
		log.Printf(err.Error())
		return err
	}
	_, err = io.Copy(buf, st)
	if err != nil {
		log.Printf(err.Error())
		return err
	}

	xmlMeta := new(meta)

	err = xml.Unmarshal(buf.Bytes(), xmlMeta)
	if err != nil {
		log.Printf(err.Error())
		return err
	}

	//r, err := zip.OpenReader("uzip.zip")
	r, err := zip.NewReader(bytes.NewReader(dzip), int64(len(dzip)))
	if err != nil {
		log.Printf("Can not open zip")
		return err
	}
	//defer r.Close()

	var fm os.FileMode //создаю папку для извлечения
	err = os.Mkdir("extract", fm)
	p := "./extract"

	i := 0 //счетчик для метаданных
	for _, f := range r.File {

		dirs, _ := filepath.Split(f.Name)
		//CrtDir(p, dirs)
		//log.Print(f.Name, " ", f.ExternalAttrs)
		if f.ExternalAttrs == 0 { //Если папка, то равно 0, если файл, то не равно 0
			//err = os.Mkdir(p+"//"+f.Name, fm)
			err = os.Mkdir(filepath.Join(p, dirs), fm)
			//log.Printf(dirs)
			if err != nil {
				//log.Printf("Dir exists already " + dirs)
			}

		} else {

			//CrtDir(p, f.Name, fm)
			rc, err := f.Open()
			defer rc.Close()
			if err != nil {
				log.Printf(err.Error())
			}

			//file, err := os.Create(p + "//" + f.Name)
			file, err := os.Create(filepath.Join(p, f.Name))
			//log.Printf(filepath.Join(p, f.Name))
			if err != nil {
				log.Printf(err.Error())
			}
			defer file.Close()
			//log.Printf("lol")

			_, err = io.Copy(file, rc)
			if err != nil {
				log.Printf(err.Error())
			}

			//вычисляю хэш
			h := sha1.New()
			fileHash, err := ioutil.ReadFile(filepath.Join(p, f.Name))
			h.Write(fileHash)
			hash := base64.URLEncoding.EncodeToString(h.Sum(nil))

			if hash == xmlMeta.File[i].Hash {
				fmt.Printf(f.Name + " hashes are equal\n")
			} else {
				fmt.Printf(f.Name + " hash is broken!\n")
			}

			i++
		}
	}
	return nil
}

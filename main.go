// Laba1 project main.go
package main

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"

	"crypto/sha256"

	//"crypto/tls"
	//"crypto/x509"
	//"encoding/pem"
	"crypto"
	"fmt"

	//"errors"
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
var Hash string

//var FileNames string

func init() {
	flag.StringVar(&Path, "path", "", "Here you should place Path")
	flag.StringVar(&Output, "out", "done.zip", "Here you should place Name of your zip")
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
		for _, file := range List {
			file = strings.Replace(file, p, "", -1)
			log.Printf(file)
		}
	case "s":
		RAS("my.crt", "my.key")
	case "i":
		//Verify("", "")
	default:
		log.Fatal("Unknown code for mode")
	}
}

/*func Verify(publicKey string, signature string) error {
	signature = "54a80a4971de10f39cfbafb3f36a42dc58062e2c077da380d712d08b6bf73bccced4a5e0263d0118ff563481c2dabd722c643629d4f2ec0e76018ecb48027cb4a4d5d45ff2c7ae3619c9b25791a703052693897a35bce6b02ce8b7dc4cf9603e640170a7ac9a079d7696fffa4ad6e752aab8188639ebcfc90627b5d0fb58ceb9e7588a1ac85b3c7593ed2509666da845b1f7869563fa6891106e9ceebdcbc2a855f7177ba12deca049ff77b58206e9f5d31a505682ac49fcb9b91fa876b82847b9c23bed909e6e0b9f9f43357900f1fd1c5875b43a4c1a043c614067c266d76db23adf4ff117bff879d582fe19614a45e8796655e06e8b15170602292bf2feef"
	publicKey = "&{27016534126922544391457751200816168784656663634955365135455735750263867483674066702928506830941162478489862493647913430738888261574130784700753084822032999203796874585015568701404272558897477780828323325265660638662591677510740474300814719248157997540440436268254930745962893322114176783645399919744708304322267872045899539218625550251506830425521129508286198661000116758111485016985005036294650288826801036019292952621592257411882238593466419793267943799557280128033453775267369236201796994363863214950792505102154317671447855522750134125210821890808126380493963465803315541396862479496365663176430785971718972448279 65537}"
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	newhash := crypto.SHA256
	pssh := sha256.New()
	hashed := pssh.Sum(nil)
	err := rsa.VerifyPSS(publicKey, newhash, hashed, []byte(signature), &opts)
	if err != nil {
		fmt.Println("Who are U? Verify Signature failed")
		os.Exit(1)
	} else {
		fmt.Println("Verify Signature successful")
	}
	return nil
}*/

func RAS(certFile, keyFile string) error {
	data, err := ioutil.ReadFile(Output)
	myPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println(err.Error)
		os.Exit(1)
	}

	myPublicKey := &myPrivateKey.PublicKey

	if err != nil {
		fmt.Println(err.Error)
		os.Exit(1)
	}

	fmt.Println("Private Key : ", myPrivateKey)
	fmt.Println("Public key ", myPublicKey)

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := data
	//log.Printf("Hello")
	newhash := crypto.SHA256
	//log.Printf("Hello")
	pssh := sha256.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, myPrivateKey, newhash, hashed, &opts)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("PSS Signature : %x\n", signature)

	newFile, err := os.Create("szip.szp")
	if err != nil {
		return err
	}

	newFile.Write([]byte(signature))
	if err != nil {
		return err
	}
	newFile.Write([]byte("4"))
	if err != nil {
		return err
	}
	newFile.Write(data)
	if err != nil {
		return err
	}
	return nil
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

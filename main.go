// Laba1 project main.go
package main

import (
	"archive/zip"
	//	"crypto/rand"
	//"crypto/rsa"

	//"crypto/sha256"

	//"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	//"crypto"
	"errors"
	"flag"

	//"fmt"
	"encoding/xml"
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
		RAS("my.crt", "my.key")
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

	//v := &File{Name: "readme.txt", Size: 10}

	output, err := xml.MarshalIndent(list, "  ", "    ")
	if err != nil {
		log.Printf("error: %v\n", err)
		return err
	}

	f.Write(output)
	return nil
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
	log.Printf("hello1")
	if err != nil {
		log.Printf("hello")
		return err
	}
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Printf("hello21")
		return err
	}
	log.Printf("hello2")
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		log.Printf("failed to parse PEM block containing the public key")
		return errors.New("Bad cert")
	}

	/*pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("failed to parse x509")
		return err
	}*/
	log.Printf("hello7")
	certif, err := x509.ParseCertificate([]byte(key))
	if err != nil {
		log.Printf(err.Error())
		return err
	}
	log.Printf("hello5")
	prv, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		return err
	}
	signedData, err := pkcs7.NewSignedData([]byte(data))
	if err != nil {
		log.Printf("Cannot initialize signed data: %s", err)
		return err
	}
	if err := signedData.AddSigner(certif, prv, pkcs7.SignerInfoConfig{}); err != nil {
		log.Printf("Cannot add signer: %s", err)
		return err
	}

	signedData.Detach()

	detachedSignature, err := signedData.Finish()
	if err != nil {
		log.Printf("Cannot finish signing data: %s", err)
		return err
	}
	sdata := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: detachedSignature})
	sz, err := os.Create("szip.szp")
	defer sz.Close()
	if err != nil {
		return err
	}
	sz.Write(sdata)

	/*myPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)

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
	*/
	/*newFile.Write([]byte(signature))
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
	}*/
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

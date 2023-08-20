package main

import (
	"bcryptor/models"
	"bcryptor/page"
	"embed"
	"flag"
	"fmt"
	"github.com/gorilla/csrf"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	configuration models.Config

	//go:embed views/*
	views embed.FS
)

const MAXLENGTH = 32

func main() {
	pid := os.Getpid()
	err := os.WriteFile("application.pid", []byte(strconv.Itoa(pid)), 0666)
	if err != nil {
		log.Fatal(err)
	}

	var configLocation string
	flag.StringVar(&configLocation, "config", "config.yml", "Set the location of configuration file")
	flag.Parse()

	loadConfiguration(configLocation, &configuration)

	router := httprouter.New()
	router.HandlerFunc("GET", fmt.Sprintf("%s%s", configuration.HTTP.BasePath, "/"), indexHandler)
	router.HandlerFunc("POST", fmt.Sprintf("%s%s", configuration.HTTP.BasePath, "/"), indexHandler)
	router.HandlerFunc("POST", fmt.Sprintf("%s%s", configuration.HTTP.BasePath, "/check"), checkHashHandler)

	csrfProtection := csrf.Protect(generateRandomBytes(32))
	port := strconv.Itoa(configuration.HTTP.Port)
	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      csrfProtection(router),
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	if configuration.HTTP.IsTLS {
		log.Printf("Server running at https://localhost:%s%s/\n", port, configuration.HTTP.BasePath)
		log.Fatal(httpServer.ListenAndServeTLS(configuration.HTTP.ServerCert, configuration.HTTP.ServerKey))
		return
	}
	log.Printf("Server running at http://localhost:%s%s/\n", port, configuration.HTTP.BasePath)
	log.Fatal(httpServer.ListenAndServe())
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		{
			p := page.New()
			p.Title = "Bcryptor"
			p.CSRFToken = csrf.Token(r)
			renderPage(w, r, p, configuration.HTTP.BasePath, "views/base.html", "views/index.html")
		}
	case http.MethodPost:
		{
			plaintext := strings.Trim(r.FormValue("plaintext"), " ")
			if len(plaintext) > MAXLENGTH {
				plaintext = plaintext[0:MAXLENGTH]
			}

			hashedPlaintext, err := bcryptPlaintext(plaintext)
			if err != nil {
				log.Println(err)
				return
			}

			p := page.New()
			p.Title = "Bcryptor"
			p.CSRFToken = csrf.Token(r)

			data := make(map[string]interface{})
			data["hashedPlaintext"] = hashedPlaintext

			p.SetData(data)
			renderPage(w, r, p, configuration.HTTP.BasePath, "views/base.html", "views/hashed-plaintext.html")
		}
	default:
		{
		}
	}
}

func checkHashHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		{
			bcryptHash := strings.Trim(r.FormValue("bcryptHash"), " ")
			plaintext := strings.Trim(r.FormValue("plaintext"), " ")
			if len(plaintext) > MAXLENGTH {
				plaintext = plaintext[0:MAXLENGTH]
			}

			match := checkBcryptHash(bcryptHash, plaintext)

			p := page.New()
			p.Title = "Bcryptor"
			p.CSRFToken = csrf.Token(r)

			data := make(map[string]interface{})
			if match {
				data["result"] = "Match"
			} else {
				data["result"] = "Not Match"
			}

			p.SetData(data)
			renderPage(w, r, p, configuration.HTTP.BasePath, "views/base.html", "views/check-bcrypt-hash.html")
		}
	default:
		{
		}
	}
}

func bcryptPlaintext(plaintext string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkBcryptHash(bcryptHash string, plaintext string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte(plaintext))
	if err != nil {
		return false
	}
	return true
}

func renderPage(w http.ResponseWriter, r *http.Request, vm interface{}, basePath string, filenames ...string) {
	p := vm.(*page.Page)

	if p.Data == nil {
		p.SetData(make(map[string]interface{}))
	}

	if p.ErrorMessages == nil {
		p.ResetErrors()
	}

	if p.UIMapData == nil {
		p.UIMapData = make(map[string]interface{})
	}
	p.UIMapData["basePath"] = basePath
	templateFS := template.Must(template.New("base").ParseFS(views, filenames...))
	err := templateFS.Execute(w, p)
	if err != nil {
		log.Panic(err.Error())
	}
}

// This will handle the loading of config.yml
func loadConfiguration(a string, b *models.Config) {
	f, err := os.Open(a)
	if err != nil {
		log.Fatal(err.Error())
	}

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(b)
	if err != nil {
		log.Fatal(err.Error())
	}
}

func generateRandomBytes(length int) []byte {
	s := ""
	for i := 33; i <= 126; i++ {
		s = s + fmt.Sprintf("%c", i)
	}
	rs := make([]byte, 0)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < length; i++ {
		delta := rand.Intn(len(s))
		rs = append(rs, s[delta])
	}
	return rs
}

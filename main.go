package main

import (
	"bcryptor/models"
	"bcryptor/page"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/csrf"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"
)

var (
	configuration models.Config

	//go:embed views/*
	views embed.FS
)

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
	router.HandlerFunc(http.MethodGet, fmt.Sprintf("%s%s", configuration.HTTP.BasePath, "/"), indexHandler)
	router.HandlerFunc(http.MethodPost, fmt.Sprintf("%s%s", configuration.HTTP.BasePath, "/check"), func(w http.ResponseWriter, r *http.Request) {
		var checkDto models.CheckModel
		buffer, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 200))
		defer r.Body.Close()
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(buffer, &checkDto)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		isMatch := checkBcryptHash(checkDto.CheckHashedText, checkDto.CheckPlaintext)
		w.Header().Add("Content-Type", "application/json")
		_, _ = w.Write([]byte(strconv.FormatBool(isMatch)))
	})
	router.HandlerFunc(http.MethodPost, fmt.Sprintf("%s%s", configuration.HTTP.BasePath, "/hash"), func(w http.ResponseWriter, r *http.Request) {
		var hashDto models.HashModel
		buffer, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 200))
		defer r.Body.Close()
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(buffer, &hashDto)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		hashedValue, _ := bcryptPlaintext(hashDto.Plaintext)
		w.Header().Add("Content-Type", "application/json")
		_, _ = w.Write([]byte(hashedValue))
	})

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
	p := page.New()
	p.Title = "Bcryptor"
	p.CSRFToken = csrf.Token(r)
	renderPage(w, r, p, configuration.HTTP.BasePath, "views/base.html", "views/index.html")
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

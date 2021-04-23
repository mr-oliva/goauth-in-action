package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/mr-oliva/goauth-in-action/db"
)

type authServer struct {
	authorizationEndpoint string
	tokenEndpoint         string
	requests              map[string]url.Values
	codecs                map[string]struct{ request url.Values }
	db                    db.DB
}

type client struct {
	id           string
	secret       string
	redirectURIs []string
}

var (
	clients = []client{
		{
			id:           "oauth-client-1",
			secret:       "oauth-client-secret-1",
			redirectURIs: []string{"http://localhost:9000/callback"},
		},
	}
	scope     = "foo bar"
	emptyCode = struct{ request url.Values }{}
)

func (a *authServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	index := struct {
		ClientID              string
		ClientSecret          string
		ClientScope           string
		ClientRedirectURI     string
		AuthorizationEndpoint string
		TokenEndpoint         string
	}{
		ClientID:              "",
		ClientSecret:          "",
		ClientScope:           scope,
		ClientRedirectURI:     "",
		AuthorizationEndpoint: a.authorizationEndpoint,
		TokenEndpoint:         a.tokenEndpoint,
	}
	render(w, "public/authorization/index.tpl", index)
}

func (a *authServer) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	idInReq := r.URL.Query().Get("client_id")
	requestClient, err := getClient(idInReq)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	redirectURIInReq := r.URL.Query().Get("redirect_uri")
	if err := checkRedirectURI(requestClient.redirectURIs, redirectURIInReq); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	reqID := randomString(8)
	a.requests[reqID] = r.URL.Query()

	render(w, "public/authorization/approve.tpl", struct {
		ClientName    string
		ClientID      string
		ClientURI     string
		ClientLogoURI string
		ReqID         string
	}{"", requestClient.id, "", "", reqID})
}

func (a *authServer) handleApprove(w http.ResponseWriter, r *http.Request) {
	e := r.ParseForm()
	log.Println(e)
	reqID := r.Form.Get("reqid")
	query := a.requests[reqID]
	log.Printf("query: %v\n", query)
	delete(a.requests, reqID)

	if query.Get("redirect_uri") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Form.Get("approve") == "" {
		w.WriteHeader(http.StatusBadRequest)
		render(w, "public/authorization/error.tpl", struct {
			error string
		}{"No matching authorization request"})
		return
	}

	if query.Get("response_type") != "code" {
		redirectURL, err := url.ParseRequestURI(query.Get("redirect_uri"))
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		parameter := redirectURL.Query()
		parameter.Add("error", "unsupported_response_type")
		redirectURL.RawQuery = parameter.Encode()
		log.Printf("in case not 'code': redirect to %s", redirectURL.String())
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	}

	code := randomString(8)
	a.codecs[code] = struct{ request url.Values }{query}
	redirectURL, err := url.ParseRequestURI(query.Get("redirect_uri"))
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	parameter := redirectURL.Query()
	parameter.Add("code", code)
	parameter.Add("state", query.Get("state"))
	redirectURL.RawQuery = parameter.Encode()

	log.Printf("in case 'code': redirect to %s", redirectURL.String())
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (a *authServer) handleToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	auth := r.Header.Get("Authorization")
	var clientID, clientSecret string
	var err error
	if auth != "" {
		clientID, clientSecret, err = decodeCredentials(auth)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	if r.Form.Get("client_id") != "" {
		if clientID != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	client, err := getClient(clientID)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if client.secret != clientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	grantType := r.Form.Get("grant_type")
	if grantType != "authorization_code" && grantType != "refresh_token" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	type tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	if grantType == "authorization_code" {
		code := a.codecs[r.Form.Get("code")]
		if reflect.DeepEqual(code, emptyCode) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if code.request.Get("client_id") != clientID {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		accessToken := randomString(10)
		refreshToken := randomString(10)
		log.Printf("access token: %s, refresh token: %s, code: %v\n", accessToken, refreshToken, code)

		a.db.Insert(struct {
			AccessToken string `json:"access_token"`
			ClientID    string `json:"client_id"`
		}{accessToken, clientID})
		a.db.Insert(struct {
			RefreshToken string `json:"refresh_token"`
			ClientID     string `json:"client_id"`
		}{refreshToken, clientID})

		delete(a.codecs, clientID)

		response := &tokenResponse{accessToken, refreshToken, "Bearer"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	if grantType == "refresh_token" {
		refreshTokenInReq := r.Form.Get("refresh_token")
		type Token struct {
			RefreshToken string
			ClientID     string
		}
		data, err := a.db.Where("refresh_token", refreshTokenInReq)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		refreshTokenInDB := data["refresh_token"].(string)
		clientIDInDB := data["client_id"].(string)
		log.Printf("refreshTokenInDB: %s, clientIDInDB: %s\n", refreshTokenInDB, clientIDInDB)

		if clientIDInDB != clientID {
			if err := a.db.Remove("refresh_token", refreshTokenInReq); err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		accessToken := randomString(10)
		a.db.Insert(struct {
			AccessToken string `json:"access_token"`
			ClientID    string `json:"client_id"`
		}{accessToken, clientID})
		response := &tokenResponse{accessToken, refreshTokenInDB, "Bearer"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

// --- util methods ---

func getClient(clientID string) (client, error) {
	for _, client := range clients {
		if client.id == clientID {
			return client, nil
		}
	}
	err := fmt.Errorf("unkown client: %s", clientID)
	return client{}, err
}

func checkRedirectURI(redirectURIs []string, redirectURIInReq string) error {
	for _, u := range redirectURIs {
		if u == redirectURIInReq {
			return nil
		}
	}
	return fmt.Errorf("mismatched redirect URI, expected %v got %s", redirectURIs, redirectURIInReq)
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func decodeCredentials(auth string) (string, string, error) {
	auth = strings.Trim(auth, "Basic ")
	log.Printf("auth: %s", auth)
	decordedBytes, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", err
	}
	log.Printf("decorded message: %s\n", string(decordedBytes))
	credentials := strings.Split(string(decordedBytes), ":")
	return credentials[0], credentials[1], nil
}

func render(w http.ResponseWriter, path string, content interface{}) {
	tpl := template.Must(template.ParseFiles(path))
	tpl.Execute(w, content)
}

// --- main ---

func main() {
	flag.Parse()
	args := flag.Args()
	originalRepoTargetDir := args[0]
	file := db.File{Name: originalRepoTargetDir + "database.nosql"}
	a := &authServer{
		authorizationEndpoint: "http://localhost:9001/authorize",
		tokenEndpoint:         "http://localhost:9001/token",
		requests:              map[string]url.Values{},
		codecs:                map[string]struct{ request url.Values }{},
		db:                    &file,
	}
	http.HandleFunc("/authorize", a.handleAuthorization)
	http.HandleFunc("/approve", a.handleApprove)
	http.HandleFunc("/token", a.handleToken)
	http.HandleFunc("/", a.handleIndex)
	if err := http.ListenAndServe(":9001", nil); err != nil {
		log.Fatal(err)
	}
}

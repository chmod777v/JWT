package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey []byte = []byte("I4C0wQp8Lv29Dv5W2l14mc3GlX4RtYb21f5epeWpA_k")

type Claims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	Admin    bool   `json:"admin"`
}
type User struct {
	Username string
	Admin    bool
	Token    string
}

func NewToken(username string, admin bool, durations time.Duration) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(durations)),
		},
		Username: username,
		Admin:    admin,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
func ParseValidateToken(tokenString string) (*Claims, error) {
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неправильынй метод подписи")
		}
		return secretKey, nil
	}

	claims := &Claims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("Ошибка разбора: %v", err)
	}
	if !parsedToken.Valid {
		return nil, fmt.Errorf("Недействительный токен")
	}

	return claims, nil
}

func getToken(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Println("Erro while receiving data", "ERROR", err.Error())
		return
	}
	token, err := NewToken(user.Username, user.Admin, time.Minute)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(token)
	w.Write([]byte(token))
}

func postToken(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Println("Erro while receiving data", "ERROR", err.Error())
		return
	}
	fmt.Println(user.Token)
	claims, err := ParseValidateToken(user.Token)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(claims.Username, claims.Admin)
	w.Write([]byte(fmt.Sprintln(claims.Username, claims.Admin)))

}

func main() {
	token, err := NewToken("ivan", true, time.Minute)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	claims, err := ParseValidateToken(token)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(claims.Username, claims.Admin)

	http.HandleFunc("/get-token", getToken)
	http.HandleFunc("/post-token", postToken)
	fmt.Println("START")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error starting server", "ERROR", err.Error())
		return
	}
}

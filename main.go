package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey []byte = []byte("I4C0wQp8Lv29Dv5W2l14mc3GlX4RtYb21f5epeWpA_k")

type Claims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	Admin    bool   `json:"admin"`
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

func main() {
	token, err := NewToken("ivan", true, time.Second)
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
}

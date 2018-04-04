package auth

import (
  "fmt"

  "github.com/nu7hatch/gouuid"
)

// RandToken Generation token
func RandToken() (string, error) {
  // Using UUID V5 for generating the Token
  u4, err := uuid.NewV4()
  UUIDtoken := u4.String()
  if err != nil {
    fmt.Println("error:", err)
    return "",err
  }
  fmt.Println("V4 UUID is",u4)

  return UUIDtoken,nil
}

package auth

import (
  "time"

  "github.com/go-redis/redis"
  "github.com/sirupsen/logrus"
)

// Client is setting connection with redis
var Client = redis.NewClient(&redis.Options{
Addr:     "localhost:6379",
Password: "", // no password set
DB:       0,  // use default DB
})


// SetValue sets the key value pair
func SetValue (key string, value string, expiry time.Duration) (er error) {
  errr := Client.Set(key, value, expiry).Err()
  if errr != nil {
    logrus.Debug("Error in setting the state variable ",errr)
    return errr
  }
  return
}

// GetValue the value corresponding to a given key
func GetValue (key string) (string, error) {
  value, arghhh := Client.Get(key).Result()
  if arghhh != nil {
    logrus.Debug("Error in getting the state variable ",arghhh)
    return "",arghhh
  }
  return value,nil
}

// CreateAuthSession will create Auth session
func CreateAuthSession (key int64) (string,error) {
  sessionPass, err := RandToken()
  if err != nil {
    return "",err
  }
  er := SetValue(string(key),sessionPass,259200*time.Second)
  return sessionPassword,er
}


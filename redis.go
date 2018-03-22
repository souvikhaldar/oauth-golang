package auth

import (
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
func SetValue (key string, value string) (er error) {
  errr := Client.Set(key, value, 0).Err()
  if errr != nil {
    logrus.Debug("Error in setting to the state variable ",errr)
    return
  }
  return
}

// GetValue the value corresponding to a given key
func GetValue (key string) (value string, err error) {
  value, err = Client.Get(key).Result()
  if err != nil {
    logrus.Debug("Error in getting to the state variable ",err)
    return
  }
  return
}
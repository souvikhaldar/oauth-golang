package auth
import (
  "crypto/rand"
  "encoding/base64"
  "encoding/json"
  "io/ioutil"
  "log"
  "net/http"
  "github.com/gin-gonic/gin"
  "github.com/sirupsen/logrus"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/google"
)

const AuthenticUserId = "userid"

type Email struct  {
  Sub string `json:"sub"`
  Name string `json:"name"`
  GivenName string `json:"given_name"`
  FamilyName string `json:"family_name"`
  Profile string `json:"profile"`
  Picture string `json:"picture"`
  Email string `json:"email"`
  EmailVerified bool `json:"email_verified"`
}



func AuthRequired() gin.HandlerFunc {
  return func(c *gin.Context) {
    // after authentication succeeds the result is
    // the user id. Add this to context so the
    // router handlers will be able to get it.
    // note that route handlers will be executed
    // after this function since this is middleware
    c.Set(AuthenticUserId, "<authenticated user id>")
    logrus.Debug("In auth middleware")
  }
}


// Credentials contains the client id and client secret generated during app registration
type Credentials struct {
  Cid string `json:"cid"`
  Csecret string `json:"csecret"`
}

// User is the retrieved user data
type User struct {
  Sub string `json:"sub"`
  Name string `json:"name"`
  GivenName string `json:"given_name"`
  FamilyName string `json:"family_name"`
  Profile string `json:"profile"`
  Picture string `json:"picture"`
  Email string `json:"email"`
  EmailVerified bool `json:"email_verified"`
  Gender string `json:"gender"`
}

var cred Credentials
var conf *oauth2.Config
var state string


func randToken() string {
  b := make([]byte,32)
  rand.Read(b)
  return base64.StdEncoding.EncodeToString(b)
}

func getLoginURL(state string) string {
  // State can be some kind of random generated hash string.
  // See relevant RFC: http://tools.ietf.org/html/rfc6749#section-10.12
  return conf.AuthCodeURL(state)
}
// StartSocialAuth for logging user in
func StartSocialAuth(c *gin.Context){
  // Initializing the credentials
  file, err := ioutil.ReadFile("/Users/souvikhaldar/Development/go/src/gitlab.com/multitech/go_server/auth/creds.json")
  if err != nil {
    logrus.Debug("Failed to read the creds file ",err)
  }
  if er := json.Unmarshal(file,&cred); err != nil {
    logrus.Debug("Unmarshalling failed ",er)
  }

  conf = &oauth2.Config {
    ClientID: cred.Cid,
    ClientSecret:cred.Csecret,
    RedirectURL:"http://127.0.0.1:8192/login/social/credentials",
    Scopes: []string{
      "https://www.googleapis.com/auth/userinfo.email", // Not sure about this but look-> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
    },
    Endpoint:google.Endpoint,
  }



  state = randToken()
  // Not using sessions anymore rather redis
  //session := sessions.Default(c)
  //session.Set("state", state)
  //session.Save()
  SetValue("state",state)

  url := getLoginURL(state)
  // http.Redirect(c.Writer,c.Request,url,303)
  c.Redirect(303,url)

}

func FinishSocialAuth(c *gin.Context) {
  // Handle the exchange code to initiate a transport.
  // Not using sessions instead redis
  // session := sessions.Default(c)
  retrievedState, er := GetValue("state")
  if er != nil {
    logrus.Debug("Error in getting state from redis ",er)
    return
  }

  if retrievedState != c.Query("state") {
    logrus.Debug("Cross-site request forgery attack possibility")
    c.JSON(http.StatusBadRequest,retrievedState)
    return
  }

  tok, err := conf.Exchange(oauth2.NoContext , c.Query("code"))
  if err != nil {
    logrus.Debug("Code not right ",err)
    c.JSON(http.StatusBadRequest, err)
    return
  }

  client := conf.Client(oauth2.NoContext, tok)
  email, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
  if err != nil {
    logrus.Debug("Error in getting user info ",err)
    c.JSON(http.StatusBadRequest, err)
    return
  }
  defer email.Body.Close()

  data, _ := ioutil.ReadAll(email.Body)
  log.Println("Email body: ", string(data))

  // for return JSON of the user info
  // c.JSON(http.StatusOK,string(data))
  var userdata Email
  json.Unmarshal(data,&userdata)
  logrus.Debug("User data is ",userdata)

  // http.Redirect(c.Writer,c.Request,url,303)
  c.Redirect(303,"http://kartbites.com/")

}
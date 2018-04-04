package auth
import (
  "database/sql"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "net/http"
  "os"
  "time"

  "github.com/gin-gonic/gin"
  "github.com/sirupsen/logrus"
  "gitlab.com/multitech/go_server/db"
  "gitlab.com/multitech/go_server/dbqueries"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/google"
)
// AuthenticUserId is the key whose value will be set inside AuthRequired
const AuthenticUserId = "userid"
var sessionPassword string
var sqldb = db.InitSqlDbDelegate()
var lastInsertId int64
var requiredUserID int64
var argh error
var conf *oauth2.Config

//cookieDataType is the data type for storing the value of the cookie
type cookieDataType struct {
  Id int64 `json:"id"`
  P string `json:"p"`
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


// Initializing and setting config data
func init() {

  conf = &oauth2.Config {
    ClientID:     os.Getenv("ClientID"),
    ClientSecret: os.Getenv("ClientSecret"),
    RedirectURL:  "http://kartbites.com:8192/login/social/credentials",
    Scopes: []string{
      "https://www.googleapis.com/auth/userinfo.email", // Not sure about this but look-> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
    },
    Endpoint:google.Endpoint,
  }
}


func AuthRequired() gin.HandlerFunc {
  return func(c *gin.Context) {
    // after authentication succeeds the result is
    // the user id. Add this to context so the
    // router handlers will be able to get it.
    // note that route handlers will be executed
    // after this function since this is middleware
    var cookieData cookieDataType

    data, er := c.Cookie("data")
    if er != nil {
      logrus.Debug("Failed to read from the cookie ",er)
      c.AbortWithStatus(400) // BAD REQUEST -> https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
      return
    }


    // Unmarshalling the data retrieved from request body
    if err := json.Unmarshal([]byte(data),&cookieData); err != nil{
      logrus.Debug("Failed to unmarshall the cookie data ",err)
      c.AbortWithStatus(400)
      return
    }

    logrus.Debug("The retrieved cookie data is",cookieData)


    retrievedSessionPassword, err := GetValue(string(cookieData.Id))
    if err != nil {
      logrus.Debug("Failed to retrieve corresponding session password ",err)
      c.AbortWithStatus(400)
      return
    }


    // Checking if the session password stored in redis matches that stored in the cookie
    if cookieData.P == retrievedSessionPassword {
      logrus.Debug("Authentication success! ")
      c.Set(AuthenticUserId, cookieData.Id)
      // It executes the pending handlers in the chain inside the calling handler
      c.Next()
    } else {
      logrus.Debug("Authentication denied! ")
      c.AbortWithStatus(401)
      return
    }

    fmt.Println("--- In Auth Middleware ---")

  }
}


func getLoginURL(state string) string {
  // State can be some kind of random generated hash string.
  return conf.AuthCodeURL(state)
}

// StartSocialAuth for logging user in
func StartSocialAuth(c *gin.Context){
  fmt.Println("---- Running StartSocialAuth ----")

  // generating state using v4 UUID
  state ,er := RandToken()
  if er != nil {
    logrus.Debug("Couldn't generate UUID ",er)
    return
  }

  // SetValue will set the value of state produced by RandToken()
  if oops := SetValue("state",state,259200*time.Second); oops != nil {
    logrus.Debug("Error in setting state ",oops)
    return
  }

  // Calling AuthURL with state as the argument
  url := getLoginURL(state)

  // Redirecting to the above acquired URL to proceed with google login
  c.Redirect(303,url)

}

// FinishSocialAuth, callback URI invokes this one
func FinishSocialAuth(c *gin.Context) {

  fmt.Println("---- Running FinishSocialAuth ----")

  // GetValue will the retrive the value of state in the variable retrievedState using redis
  retrievedState, er := GetValue("state")
  if er != nil {
    logrus.Debug("Error in getting state from redis ",er)
    return
  }
  // Checking for possible CSRF attack
  if retrievedState != c.Query("state") {
    logrus.Warn("Cross-site Request Forgery attack detected")
    c.JSON(http.StatusBadRequest,retrievedState)
    return
  }

  // Exchange converts an authorization code into a token
  tok, err := conf.Exchange(oauth2.NoContext , c.Query("code"))
  if err != nil {
    logrus.Debug("Code not right, failed to exchange for access token ",err)
    c.JSON(http.StatusBadRequest, err)
    return
  }

  // Saving the Token for furture use
  SetValue("accessToken",tok.AccessToken,259200*time.Second)

  SetValue("refreshToken",tok.RefreshToken,259200*time.Second)

  // Creating a client using the access token hence retrieved
  client := conf.Client(oauth2.NoContext, tok)

  // Getting for the user's details
  email, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
  if err != nil {
    logrus.Debug("Error in getting user info ",err)
    c.JSON(http.StatusBadRequest, err)
    return
  }
  defer email.Body.Close()

  data, er := ioutil.ReadAll(email.Body)
  if er != nil {
    logrus.Debug("Error in reading from the email body")
    c.JSON(http.StatusBadRequest, err)
    return
  }
  fmt.Println("Email body: ", string(data))

  var userdata User
  if arghh := json.Unmarshal(data,&userdata);arghh != nil {
    logrus.Debug("Failed to unmarshall user's data",arghh)
    return
  }


  result, errrr := sqldb.QueryRow(dbqueries.QUERY_ADD_EMAIL,userdata.Email)
  if errrr != nil {
    logrus.Debug("Error in inserting to the emails table ",errrr)
    c.JSON(http.StatusBadRequest, err)
    return
  }
  var id int64
  scanError:= result.Scan(&lastInsertId)
  // Checking if it's a returning user or a new user
  if scanError == sql.ErrNoRows{
    logrus.Debug("The user exists")
    result2 , eror := sqldb.QueryRow(dbqueries.QUERY_GET_EMAIL,userdata.Email)
    if eror != nil {
      logrus.Debug("Couldn't get the corresponding email",eror)
      c.JSON(http.StatusBadRequest, err)
      return
    }
    if scanError2 := result2.Scan(&id); scanError2 != nil {
      logrus.Debug("Scanning the email failed ",scanError2)
      return
    }
    logrus.Debug("The userid of the existing user is ",id)
    requiredUserID = id
    sessionPassword, argh = GetValue(string(requiredUserID))
    if argh != nil {
      logrus.Debug("Error in fetching the session password ",argh)
      return
    }
    logrus.Debug("The session password of the existing user is ",sessionPassword)

  } else {
    logrus.Debug("Userid id of the new user is ",lastInsertId)
    requiredUserID = lastInsertId
    sessionPassword, argh = CreateAuthSession(requiredUserID)
    if argh != nil {
      logrus.Debug("Error in creating auth session or retrieving from one ",argh)
      c.JSON(http.StatusBadRequest, err)
      return
    }
    logrus.Debug("The session password of the new user has been set to ",sessionPassword)
    c.JSON(http.StatusBadRequest, err)
    return

  }


  userCookieData := &cookieDataType{
    requiredUserID,
    string(sessionPassword),
  }

  userCookiedataJSON,ufff :=json.Marshal(userCookieData)
  if ufff != nil {
    logrus.Println("Failed to marshall usercookie ",ufff)
    c.JSON(http.StatusBadRequest, err)
    return
  }
  c.SetCookie("data", string(userCookiedataJSON), 15780000, "", "kartbites.com", false, false)
  c.Redirect(302,"kartbites://screen?name=social&login=true" )
  return

}

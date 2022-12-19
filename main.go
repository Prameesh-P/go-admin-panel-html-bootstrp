package main

import (
	"database/sql"
	"fmt"
	"github.com/Prameesh-P/admin-panel/Intialezer"
	"github.com/alexedwards/scs/v2"
	_ "github.com/jackc/pgx/v4/stdlib"
	_ "github.com/jackc/pgx/v5"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	http "net/http"
	"text/template"
)

var sessionManager *scs.SessionManager

var DB *gorm.DB
var tpl *template.Template
var Sessions map[string]User
var Users map[string]User
var Admins map[string]Admin

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	Password = "pramee-12345"
	dbname   = "pramee"
)

type Admin struct {
	id            int
	username      string `gorm:"not null;unique_index"`
	password      string
	password_hash string
	date_of_birth string
	place         string
}
type User struct {
	Username     string `gorm:"not null;unique_index"`
	PasswordHash string
	date         string
	place        string
}

func init() {
	Intialezer.LoadEnv()
	Admins = make(map[string]Admin)
	tpl = template.Must(template.ParseGlob("templates/*.html"))
	Sessions = make(map[string]User)
	Users = make(map[string]User)
}
func hasSessionCookie(req *http.Request) bool {
	_, err := req.Cookie("_session")
	return err != http.ErrNoCookie
}

//	func hasAdminSessionCookie(req *http.Request) bool {
//		_, err := req.Cookie("_ASession")
//		return err != http.ErrNoCookie
//	}
//
//	func getAdminSessionCookie(req *http.Request) *http.Cookie {
//		var sessionCookie *http.Cookie
//		if !hasAdminSessionCookie(req) {
//			sessionCookie = createNewAdminSessionCookie()
//		} else {
//			sessionCookie, _ = req.Cookie("_ASession")
//		}
//		return sessionCookie
//	}
func getSessionCookie(req *http.Request) *http.Cookie {
	var sessionCookie *http.Cookie
	if !hasSessionCookie(req) {
		sessionCookie = createNewSessionCookie()
	} else {
		sessionCookie, _ = req.Cookie("_session")
	}
	return sessionCookie
}
func loggedIn(sessionCookie *http.Cookie) bool {
	_, ok := Sessions[sessionCookie.Value]
	return ok
}

//	func AdminLoggedIn(sessionCookie *http.Cookie) bool {
//		_, ok := Admins[sessionCookie.Value]
//		return ok
//	}
func createNewSessionCookie() *http.Cookie {
	id := uuid.NewV4()
	c := &http.Cookie{
		Name:  "_session",
		Value: id.String(),
	}
	return c
}

//	func createNewAdminSessionCookie() *http.Cookie {
//		id := uuid.NewV4()
//		c := &http.Cookie{
//			Name:  "_ASession",
//			Value: id.String(),
//		}
//		return c
//	}
func root(res http.ResponseWriter, req *http.Request) {
	var context User
	sessionCookie := getSessionCookie(req)
	http.SetCookie(res, sessionCookie)
	if !loggedIn(sessionCookie) {
		http.SetCookie(res, sessionCookie)
		context = User{Username: "Guest"}
	} else {
		context = Sessions[sessionCookie.Value]
	}
	tpl.ExecuteTemplate(res, "index.html", context)
}
func signup(res http.ResponseWriter, req *http.Request) {
	sessionCookie := getSessionCookie(req)
	http.SetCookie(res, sessionCookie)
	if loggedIn(sessionCookie) {
		http.Redirect(res, req, "/bar", http.StatusSeeOther)
		return
	}
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")
		dob := req.FormValue("dob")
		place := req.FormValue("place")
		_, exists := Users[username]
		if exists {
			msg := "Username already exists"
			fs := http.FileServer(http.Dir("templates"))
			http.Handle("/css/", fs)
			tpl.ExecuteTemplate(res, "signup.html", msg)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Panic(err)
		}
		Users[username] = User{Username: username, PasswordHash: string(hash)}
		conn, err := gorm.Open("pgx", "host=localhost port=5432 dbname=pramee user=postgres password=pramee-12345")
		if err != nil {
			log.Fatal(fmt.Printf("unable to connect..%v\n", err))
		}
		defer conn.Close()
		stmt := `INSERT INTO userdata(username,password,password_hash,date_of_birth,place) VALUES ($1,$2,$3,$4,$5)`
		conn.Exec(stmt, username, password, hash, dob, place)
		http.Redirect(res, req, "/login", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "signup.html", nil)
}
func bar(res http.ResponseWriter, req *http.Request) {
	sessionCookie := getSessionCookie(req)
	http.SetCookie(res, sessionCookie)
	if !loggedIn(sessionCookie) {
		http.Redirect(res, req, "/login", http.StatusSeeOther)
	}
	user := Sessions[sessionCookie.Value]
	tpl.ExecuteTemplate(res, "bar.html", user)
	fs := http.FileServer(http.Dir("templates"))
	http.Handle("/css/", fs)
}
func login(res http.ResponseWriter, req *http.Request) {
	sessionCookie := getSessionCookie(req)
	http.SetCookie(res, sessionCookie)
	if loggedIn(sessionCookie) {
		http.Redirect(res, req, "/bar", http.StatusSeeOther)
		return
	}
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")
		user, ok := Users[username]
		if !ok {
			msg := "User not found"
			tpl.ExecuteTemplate(res, "login.html", msg)
			return
		}
		err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
		if err != nil {
			msg := "Wrong password"
			tpl.ExecuteTemplate(res, "login.html", msg)
			return
		}
		Sessions[sessionCookie.Value] = user
		http.Redirect(res, req, "/bar", http.StatusSeeOther)
		return
	}
	msg := "Login please"
	tpl.ExecuteTemplate(res, "login.html", msg)
}
func logout(res http.ResponseWriter, req *http.Request) {
	sessionCookie := getSessionCookie(req)
	sessionCookie.MaxAge = -1
	http.SetCookie(res, sessionCookie)
	delete(Sessions, sessionCookie.Value)
	http.Redirect(res, req, "/login", http.StatusSeeOther)
}
func adminLogin(w http.ResponseWriter, r *http.Request) {
	tpl.ExecuteTemplate(w, "adminLogin.html", nil)
	if r.Method == http.MethodPost {
		admin := r.FormValue("admin")
		pass := r.FormValue("admin-pass")
		if admin == "pramee" && pass == "123" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		} else {
			msg := "invalid"
			tpl.ExecuteTemplate(w, "adminLogin.html", msg)
		}
	}
}
func admin(w http.ResponseWriter, r *http.Request) {
	var i Admin

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, Password, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT id,username,password,password_hash,date_of_birth,place FROM userdata;")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {

		if err = rows.Scan(&i.id, &i.username, &i.password, &i.password_hash, &i.date_of_birth, &i.place); err != nil {
			log.Fatal(err)
		}
		fmt.Println(i)
	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	tpl.ExecuteTemplate(w, "admin.html", i.username)
}
func main() {
	log.Println("Conneted to the database...!!!")
	http.HandleFunc("/", root)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/bar", bar)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/adminLogin", adminLogin)
	http.HandleFunc("/admin", admin)
	var add = ":8080"
	fmt.Println("port is starting on..", add)
	http.ListenAndServe(add, nil)
}

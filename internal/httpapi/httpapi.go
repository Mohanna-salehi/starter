// Package httpapi wires the pan-vault HTTP surface using Echo v4
// (https://echo.labstack.com).
//
// The contract (routes, request/response bodies, error codes) is in
// ../PROJECT.md §3.3.
//
// TODO: implement the four endpoints. Handlers stay thin: c.Bind the JSON
// request, call the inje cted dependencies, c.JSON the result.
//
// The API error body is {"error_code": "...", "message": "..."}, which is NOT
// Echo's default HTTPError shape ({"message": "..."}) — build it explicitly or
// set e.HTTPErrorHandler; do not leak the default shape. Map pan.ErrInvalidPAN
// to 400 VALIDATION_ERROR and an unknown token to 404 TOKEN_NOT_FOUND.
// Every tokenize/detokenize call must append an audit entry that never
// contains the full PAN.
package httpapi

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"example.com/pan-vault/internal/database"
	"example.com/pan-vault/internal/model"
	"example.com/pan-vault/internal/pan"
	"example.com/pan-vault/internal/redact"
	"example.com/pan-vault/internal/repository"
	"example.com/pan-vault/internal/vault"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/gorm"
)

const UserContextKey = "user"

var Key = []byte("secret")

type Audit = model.Audit
type User = model.User

type AuditRepository interface {
	Add(Audit) error
	FindById(id uint) (Audit, error)
	FindAll() ([]Audit, error)
}

type UserRepository interface {
	Add(User) error
	FindById(id uint) (User, error)
	FindByUsername(username string) (User, error)
	FindAll() ([]User, error)
}

// implementations; tests pass fakes. Nothing in this package reaches for a
// global or builds its own vault — that is the DI rule for this project.
type Deps struct {
	// Vault stores token -> PAN mappings.
	Vault vault.Vault
	// LogOutput receives Echo's logs. New wraps it in the redacting writer,
	// so framework logs cannot leak a PAN.
	LogOutput io.Writer
	DB        *gorm.DB
}

// Server holds the handler dependencies. New builds a fresh one per process;
// tests build one per test so state does not leak between cases.
type Server struct {
	vault vault.Vault
	// TODO: add the audit store here, injected via Deps, once it exists.
	//audits          []Audit
	users           []User
	mutex           sync.RWMutex
	UserRepository  UserRepository
	AuditRepository AuditRepository
}

// New returns the Echo app with all routes attached and dependencies injected.
//
// TODO: reject nil Deps fields loudly at startup.
func New(deps Deps) (*echo.Echo, error) {
	db, err := database.Connect()
	if err != nil {
		return nil, err
	}

	if deps.Vault == nil {
		panic("missing vault")
	}
	if deps.LogOutput == nil {
		panic("missing log output")
	}
	s := &Server{
		vault: deps.Vault,

		UserRepository:  repository.NewUserRepository(db),
		AuditRepository: repository.NewAuditRepository(db),
	}

	defaultUser := os.Getenv("DEFAULT_USER")
	defaultPass := os.Getenv("DEFAULT_PASS")

	err = s.UserRepository.Add(User{
		Username: defaultUser,
		Password: defaultPass,
	})
	if err != nil && !errors.Is(err, repository.ErrDuplicated) {
		return nil, err
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	// Log lines end in '\n', so the redacting writer flushes per line; a
	// trailing partial digit run stays buffered (never written) if the
	// process exits mid-line.
	//e.Logger.SetOutput(deps.LogOutput)
	e.Logger.SetOutput(redact.NewWriter(deps.LogOutput))

	jwtMiddleware := echojwt.WithConfig(echojwt.Config{
		SigningKey: Key,
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return &jwt.RegisteredClaims{}
		},
		ContextKey: UserContextKey,
	})

	e.POST("/v1/tokenize", s.handleTokenize, jwtMiddleware)
	e.POST("/v1/detokenize", s.handleDetokenize, jwtMiddleware)
	e.POST("/v1/mask", s.handleMask, jwtMiddleware)

	e.GET("/v1/audit", s.handleAudit, middleware.BasicAuth(
		func(username string, password string, context echo.Context) (bool, error) {
			if username != "admin" || password != "admin" {
				return false, fmt.Errorf("user is not allowed")
			}
			return true, nil
		},
	))
	e.POST("/v1/login", s.handleLogin)

	e.GET("/healthz", handleHealth)

	return e, nil
}

func (s *Server) appendAudit(a Audit) {
	//s.mutex.Lock()
	//defer s.mutex.Unlock()
	//s.audits = append(s.audits, a)
	err := s.AuditRepository.Add(a)
	if err != nil {
		return
	}
}

func GenerateToken(username string) (string, error) {

	Claims := jwt.RegisteredClaims{
		//Subject: strconv.Itoa(int(id)),
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	//token := jwt.New(jwt.SigningMethodHS256)
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		Claims,
	)

	tokenStr, err := token.SignedString(Key)
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

// TODO: implement: bind {"pan": "..."}, validate, tokenize, respond
// {"token": "...", "masked": "..."}.
func (s *Server) handleTokenize(c echo.Context) error {
	var req struct {
		Pan string `json:"pan"`
	}

	userToken := c.Get(UserContextKey).(*jwt.Token)
	claims := userToken.Claims
	username, err := claims.GetSubject()

	err = c.Bind(&req)
	if err != nil {
		s.appendAudit(Audit{
			User:   username,
			Action: "tokenize",
			OK:     false,
		})

		return c.JSON(http.StatusBadRequest, echo.Map{
			"error_code": "VALIDATION_ERROR",
			"message":    "invalid request",
		})
	}

	mask, err := pan.Mask(req.Pan)
	if err != nil {
		s.appendAudit(Audit{
			User:   username,
			Action: "tokenize",
			OK:     false,
		})

		return c.JSON(http.StatusBadRequest, echo.Map{
			"error_code": "VALIDATION_ERROR",
			"message":    "invalid request",
		})
	}
	if !pan.IsLuhnValid(req.Pan) {
		s.appendAudit(Audit{
			User:   username,
			Action: "tokenize",
			Mask:   mask,
			OK:     false,
		})

		return c.JSON(http.StatusBadRequest, echo.Map{
			"error_code": "VALIDATION_ERROR",
			"message":    "invalid pan",
		})
	}

	token, err := vault.NewToken()
	if err != nil {
		s.appendAudit(Audit{
			User:   username,
			Action: "tokenize",
			Mask:   mask,
			OK:     false,
		})

		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error_code": "INTERNAL_ERROR",
			"message":    "internal server error",
		})
	}

	err = s.vault.Store(
		c.Request().Context(),
		token,
		req.Pan,
	)
	if err != nil {
		s.appendAudit(Audit{
			User:   username,
			Action: "tokenize",
			Mask:   mask,
			OK:     false,
		})

		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error_code": "INTERNAL_ERROR",
			"message":    "internal server error",
		})
	}
	s.appendAudit(Audit{
		User:   username,
		Token:  token,
		Action: "tokenize",
		Mask:   mask,
		OK:     true,
	})

	return c.JSON(http.StatusOK, echo.Map{
		"token":  token,
		"masked": mask,
	})
}

// TODO: implement: bind {"token": "..."}, look up, respond {"pan": "..."},
// audit both hit and miss.
func (s *Server) handleDetokenize(c echo.Context) error {
	var req struct {
		Token string `json:"token"`
	}

	userToken := c.Get(UserContextKey).(*jwt.Token)
	claims := userToken.Claims
	username, _ := claims.GetSubject()

	err := c.Bind(&req)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error_code": "VALIDATION_ERROR",
			"message":    "invalid request",
		})
	}

	value, ok := s.vault.Lookup(
		c.Request().Context(),
		req.Token,
	)

	if !ok {
		s.appendAudit(Audit{
			User:   username,
			Token:  req.Token,
			Action: "detokenize",
			OK:     false,
		})
		return c.JSON(http.StatusNotFound, echo.Map{
			"error_code": "TOKEN_NOT_FOUND",
			"message":    "unknown token",
		})
	}

	mask, err := pan.Mask(value)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error_code": "INTERNAL_ERROR",
			"message":    "internal server error",
		})
	}

	s.appendAudit(Audit{
		User:   username,
		Token:  req.Token,
		Action: "detokenize",
		Mask:   mask,
		OK:     true,
	})

	return c.JSON(http.StatusOK, echo.Map{
		"pan": value,
	})
}

// TODO: implement: bind {"pan": "..."}, respond {"masked": "..."}.
func (s *Server) handleMask(c echo.Context) error {
	var req struct {
		Pan string `json:"pan"`
	}

	userToken := c.Get(UserContextKey).(*jwt.Token)
	claims := userToken.Claims
	username, _ := claims.GetSubject()

	err := c.Bind(&req)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error_code": "VALIDATION_ERROR",
			"message":    "invalid request",
		})
	}

	mask, err := pan.Mask(req.Pan)

	s.appendAudit(Audit{
		User:   username,
		Action: "mask",
		Mask:   mask,
		OK:     err == nil,
	})

	//func() {
	// defer func() {
	//    if r := recover(); r != nil {
	//       c.Logger().Error(fmt.Errorf("%v", r))
	//    }
	// }()
	// s.mutex.Lock()
	//  s.mutex.Unlock()
	// //panic("Wooo")
	// if len(s.audits)==2{
	//    s.mutex2.Lock()
	//    defer s.mutex2.Unlock()
	//    s.audits = append(s.audits, Audit{})
	// }
	//
	//}()

	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error_code": "VALIDATION_ERROR",
			"message":    "invalid request",
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"masked": mask,
	})
}

// TODO: implement: respond with the audit entries, newest first.
func (s *Server) handleAudit(c echo.Context) error {
	//s.mutex.RLock()
	//defer s.mutex.RUnlock()
	//
	//res := make([]Audit, 0, len(s.audits))
	//
	//for i := len(s.audits) - 1; i >= 0; i-- {
	//	res = append(res, s.audits[i])
	//}
	all, err := s.AuditRepository.FindAll()
	if err != nil {
		return err
	}
	res := make([]Audit, 0, len(all))

	return c.JSON(http.StatusOK, res)
}

func handleHealth(c echo.Context) error {
	return c.JSON(http.StatusOK, echo.Map{"status": "ok"})
}

func notImplemented() error {
	return echo.NewHTTPError(http.StatusNotImplemented, "not implemented")
}

func (s *Server) handleLogin(c echo.Context) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	err := c.Bind(&req)
	if err != nil {
		return err
	}
	if req.Username == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "user or password is empty")
	}
	var token string
	var ok bool

	user, err := s.UserRepository.FindByUsername(req.Username)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(user.Password)) == 1 {
		ok = true
		token, err = GenerateToken(user.Username)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid username or password")
	}
	return c.JSON(http.StatusOK, echo.Map{
		"status": "ok",
		"token":  token,
	})
}

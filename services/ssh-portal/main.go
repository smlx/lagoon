package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/smlx/lagoon/services/ssh-portal/internal/exec"
	"github.com/smlx/lagoon/services/ssh-portal/internal/keycloak"
	"github.com/smlx/lagoon/services/ssh-portal/internal/lagoon"
	lclient "github.com/smlx/lagoon/services/ssh-portal/internal/lagoon/client"
	"github.com/smlx/lagoon/services/ssh-portal/internal/lagoon/jwt"
	"go.uber.org/zap"
)

var (
	version   string
	buildTime string
)

type envConfig struct {
	jwtSecret                string
	keycloakAuthServerSecret string
	keycloakBaseURL          string
	lagoonAPI                string
}

func main() {
	// parse flags
	debug := flag.Bool("debug", false, "enable debug logging")
	port := flag.Int("port", 2222, "listen port")
	flag.Parse()
	// init logger
	var log *zap.Logger
	var err error
	if *debug {
		log, err = zap.NewDevelopment()
	} else {
		log, err = zap.NewProduction()
	}
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	log.Info("startup",
		zap.String("version", version), zap.String("buildTime", buildTime))

	// get environmental configuration
	config, err := getEnvConfig()
	if err != nil {
		log.Fatal("couldn't get environmental configuration", zap.Error(err))
	}

	k, err := keycloak.New(config.keycloakBaseURL, config.keycloakAuthServerSecret)
	if err != nil {
		log.Fatal("couldn't get keycloak client", zap.Error(err))
	}

	e, err := exec.New()
	if err != nil {
		log.Fatal("couldn't get exec client", zap.Error(err))
	}

	ssh.Handle(sessionHandler(k, e, config.lagoonAPI, config.jwtSecret, log))
	log.Fatal("server error", zap.Error(ssh.ListenAndServe(fmt.Sprintf(":%d", *port), nil)))
}

func sessionHandler(k *keycloak.Client, c *exec.Client,
	lagoonAPI, jwtSecret string, log *zap.Logger) ssh.Handler {
	return func(s ssh.Session) {
		// generate session ID
		sid := uuid.New()
		log.Info("start session", zap.String("sessionID", sid.String()))
		defer log.Info("end session", zap.String("sessionID", sid.String()))
		// generate a JWT token
		token, err := jwt.OneMinuteAdminToken(jwtSecret)
		if err != nil {
			log.Error("couldn't get JWT token", zap.Error(err),
				zap.String("sessionID", sid.String()))
			io.WriteString(s, "internal error\n")
			return
		}
		// get the lagoon client with the admin token
		l := lclient.New(lagoonAPI, token, "ssh-portal "+version, true)
		// get the user ID from lagoon
		user, err := lagoon.UserBySSHKey(context.TODO(), l, s.PublicKey())
		if err != nil {
			log.Warn("couldn't get user from SSH key", zap.Error(err),
				zap.String("sessionID", sid.String()))
			io.WriteString(s, "unknown user\n")
			return
		}
		// get the user token from keycloak
		ctoken, err := k.UserToken(user.ID)
		if err != nil {
			log.Warn("couldn't get user token", zap.Error(err))
			io.WriteString(s, "internal error\n")
			return
		}
		// get the lagoon client using the user token
		cl := lclient.New(lagoonAPI, ctoken, "ssh-portal "+version, true)
		// Now, authenticated as the user, check for SSH permissions on the
		// namespace. Here, s.User() is the ssh username - for Lagoon this is the
		// namespace name
		canSSH, err := lagoon.UserCanSSHToEnvironment(context.TODO(), cl, s.User())
		if err != nil {
			log.Warn("couldn't get user SSH permissions", zap.Error(err))
			io.WriteString(s, "internal error\n")
			return
		}
		if !canSSH {
			io.WriteString(s, "permission denied\n")
			return
		}
		// check if a pty is required
		_, _, pty := s.Pty()
		// start the command
		err = c.Exec("cli", s.User(), s.Command(), s, s.Stderr(), pty)
		if err != nil {
			log.Warn("couldn't execute command", zap.Error(err),
				zap.String("sessionID", sid.String()))
			io.WriteString(s, "couldn't execute command\n")
		}
	}
}

func getEnvConfig() (*envConfig, error) {
	config := envConfig{}
	config.lagoonAPI = os.Getenv("GRAPHQL_ENDPOINT")
	if len(config.lagoonAPI) == 0 {
		return &config, fmt.Errorf("GRAPHQL_ENDPOINT not set")
	}
	config.keycloakBaseURL = os.Getenv("KEYCLOAK_BASEURL")
	if len(config.keycloakBaseURL) == 0 {
		return &config, fmt.Errorf("KEYCLOAK_BASEURL not set")
	}
	config.keycloakAuthServerSecret =
		os.Getenv("KEYCLOAK_AUTH_SERVER_CLIENT_SECRET")
	if len(config.keycloakAuthServerSecret) == 0 {
		return &config, fmt.Errorf("KEYCLOAK_AUTH_SERVER_CLIENT_SECRET not set")
	}
	config.jwtSecret = os.Getenv("JWTSECRET")
	if len(config.jwtSecret) == 0 {
		return &config, fmt.Errorf("JWTSECRET not set")
	}
	return &config, nil
}

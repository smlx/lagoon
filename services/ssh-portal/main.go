package main

import (
	"io"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/smlx/lagoon/services/ssh-portal/internal/exec"
	"go.uber.org/zap"
)

var (
	version   string
	buildTime string
)

func main() {

	log, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	log.Info("startup",
		zap.String("version", version), zap.String("buildTime", buildTime))

	c, err := exec.New()
	if err != nil {
		log.Fatal("couldn't initialise exec", zap.Error(err))
	}

	l, err := lagoon.New()
	if err != nil {
		log.Fatal("couldn't initialise lagoon client", zap.Error(err))
	}

	k, err := keycloak.New()
	if err != nil {
		log.Fatal("couldn't initialise keycloak client", zap.Error(err))
	}

	ssh.Handle(sessionHandler(c, l, k, log))
	log.Fatal("server error", zap.Error(ssh.ListenAndServe(":2222", nil)))
}

func sessionHandler(c *exec.Client, l *lagoon.Client, k *keycloak.Client, log *zap.Logger) ssh.Handler {
	return func(s ssh.Session) {
		sid := uuid.New()
		log.Info("start connection", zap.String("sessionID", sid.String()))
		defer log.Info("end connection", zap.String("sessionID", sid.String()))
		// get the user ID from lagoon
		user, err := lagoon.UserBySSHKey(s.PublicKey)
		if err != nil {
			log.Warn("couldn't get user from SSH key", zap.Error(err))
			io.WriteString(s, "unknown user\n")
			return
		}
		// get the user token from keycloak
		token, err := keycloak.UserToken(user.ID)
		if err != nil {
			log.Warn("couldn't get user token", zap.Error(err))
			io.WriteString(s, "internal authentication error\n")
			return
		}
		// now, as the user, check for SSH permissions
		// here, s.User() is the ssh username - for Lagoon this is the namespace name
		canSSH, err := lagoon.UserCanSSHToEnvironment(s.User(), token)
		if err != nil {
			log.Warn("couldn't get user SSH permissions", zap.Error(err))
			io.WriteString(s, "internal authentication error\n")
			return
		}
		if !canSSH {
			io.WriteString(s, "permission denied\n")
			return
		}
		if err := c.Exec("cli", s.User(), s.Command(), s, s.Stderr()); err != nil {
			log.Warn("couldn't execute command", zap.Error(err), zap.String("sessionID", sid.String()))
			io.WriteString(s, "couldn't execute command\n")
		}
	}
}

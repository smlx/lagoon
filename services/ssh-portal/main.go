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

	log.Info("startup",
		zap.String("version", version), zap.String("buildTime", buildTime))

	c, err := exec.New()
	if err != nil {
		log.Fatal("couldn't initialise exec", zap.Error(err))
	}

	ssh.Handle(func(s ssh.Session) {
		sid := uuid.New()
		log.Info("start connection", zap.String("sessionID", sid.String()))
		if err := c.Exec("test", "default", s.Command(), s, s.Stderr()); err != nil {
			log.Warn("couldn't execute command", zap.Error(err), zap.String("sessionID", sid.String()))
			io.WriteString(s, "couldn't execute command\n")
		}
		log.Info("end connection", zap.String("sessionID", sid.String()))
	})

	log.Fatal("server error", zap.Error(ssh.ListenAndServe(":2222", nil)))
}

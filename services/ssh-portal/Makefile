.PHONY: push
push: docker
	docker push smlx/ssh-portal

.PHONY: docker
docker: build
	docker build . -t smlx/ssh-portal

.PHONY: build
build:
	go generate ./...
	CGO_ENABLED=0 go build -ldflags "-X main.version=$$(git describe --always) -X main.buildTime=$$(date -u +"%Y-%m-%dT%H:%M:%SZ")" .

lint:
	golint ./...

test:
	go test -cover -v ./...

deps:
	go get github.com/golang/lint/golint
	go get gopkg.in/check.v1
	go get golang.org/x/tools/cmd/cover

ci: lint test


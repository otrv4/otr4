lint:
	golint ./...

test:
	go test -cover -v ./...

deps:
	go get github.com/golang/lint/golint
	go get -t -v ./...

ci: lint test


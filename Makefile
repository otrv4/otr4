default: lint test

ci: lint test

get:
	go get -u github.com/golang/lint/golint
	go get -t -v ./...

lint:
	golint

test:
	go test -cover -v ./...

test-v:
	go test -check.vv -cover ./...

deps:
	go get github.com/golang/lint/golint
	go get -t -v ./...

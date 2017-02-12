default: lint test

ci: lint test

lint:
	golint

test:
	go test -cover -v ./...

test-v:
	go test -check.vv -cover ./...

deps:
	go get github.com/golang/lint/golint
	go get -t -v ./...

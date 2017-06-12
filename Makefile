clean:
	- rm dssss
all: clean
	go build -o dssss cmd/dssss/main.go
run: all
	./dssss

.PHONY: generate build run run-test traffic clean

IFACE ?= lo

generate:
	cd $(CURDIR) && go generate ./...

build: generate
	go build -o xdp_relay .
	go build -o testtraffic ./cmd/testtraffic/

run: build
	sudo ./xdp_relay $(IFACE)

run-test: build
	sudo SEED_TEST_DATA=1 ./xdp_relay $(IFACE)

# Run in a second terminal while run-test is active:
#   make traffic-send    — sender only
#   make traffic-recv    — receiver only
#   make traffic-both    — sender + receiver in one process
traffic-send: build
	./testtraffic send -pps 1000 -size 128

traffic-recv: build
	./testtraffic recv -v

traffic-both: build
	./testtraffic both -pps 1000 -duration 10s

clean:
	rm -f xdp_relay testtraffic relay_x86_bpfel.go relay_x86_bpfel.o

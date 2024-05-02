FROM golang:1.22

WORKDIR /usr/src/app

# Precache foreign packages 
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Build
COPY . .
RUN go build -v -o /usr/local/bin/server .

# Run
CMD ["server"]

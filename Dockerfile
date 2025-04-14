FROM golang:1.23

WORKDIR /usr/src/app
COPY go.* .

RUN go mod tidy
RUN go mod verify
RUN go mod download

COPY . .

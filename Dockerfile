FROM golang:1.23

WORKDIR /app

COPY go.* ./
RUN go mod download

COPY *.go ./

RUN go build -o /gokkreg

EXPOSE 8080

CMD ["/gokkreg"]

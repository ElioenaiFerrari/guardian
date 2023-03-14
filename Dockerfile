FROM golang:1.20-alpine

WORKDIR /app
COPY go.* .
RUN go mod tidy
COPY . .
RUN go build -buildvcs=false -ldflags '-s -w' -o ./bin ./cmd/guardian

EXPOSE 4000

CMD [ "./bin/guardian" ]
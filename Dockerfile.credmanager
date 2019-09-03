FROM golang:alpine

WORKDIR /go/src/github.com/PolarGeospatialCenter/credmanager
RUN apk add --no-cache git

ENV GO111MODULE=on
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY pkg ./pkg
RUN go build -mod=readonly -o /bin/credmanager ./cmd/credmanager


FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=0 /bin/credmanager /bin/credmanager
CMD ["/bin/credmanager"]

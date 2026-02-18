# microservices

generate Go protobuf:
- go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
- go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
- protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/identity.proto

# example
ACCESS_SECRET=myAccessSecret REFRESH_SECRET=myRefreshSecret DB_HOST=postgres DB_USER=postgres DB_PASSWORD=postgres DB_NAME=postgres docker-compose up --build

# generate SSL cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout localhost.key -out localhost.crt \
  -subj "/C=US/ST=Colorado/L=Aurora/O=Development/CN=identity-service"
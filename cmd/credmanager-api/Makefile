
test:
	echo "Testing credmanager-api"

credmanager-api:
	go build -o credmanager-api .

docker:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o credmanager-api.linux .
	docker build . -t pgc-docker.artifactory.umn.edu/credmanager-api:latest

docker-push: docker
	docker push pgc-docker.artifactory.umn.edu/credmanager-api:latest

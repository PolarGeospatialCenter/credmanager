test:
	echo "Testing Credmanager Client..."

docker:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o credmanager.linux .
	docker build . -t pgc-docker.artifactory.umn.edu/credmanager:latest

docker-push: docker
	docker push pgc-docker.artifactory.umn.edu/credmanager:latest

build:
	docker-compose build;

up:
	docker-compose up;

app:
	yarn web;

server:
	cd /server &&  yarn dev;

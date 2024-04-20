# Uni Ride Hailing Server

Uni Ride Hailing Server is wriiten in go programming language using go-fiber framework.

## Tech Stack

**Server:** Go, Fiber

**Database:** MySQL

## Installation

Download & Install Go v1.21.6

```bash
https://go.dev/dl/
```

## Run Locally

Clone the project

```bash
  git clone https://github.com/balaganapathyparthiban/UniRideHailingServer-Go
```

Go to the project directory

```bash
  cd UniRideHailingServer-Go
```

Install dependencies

```bash
  go mod tidy
```

Start the server

```bash
  go run main.go
```

## Deployment

To deploy this project run

```bash
  $ go build -o UniRideHailingSever main.go
```

## SQL Script Generate

```bash
  $ go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
  $ sqlc generate
```

## MongoDB

```bash
  - Install Docker image
  $ sudo docker pull mongo

  - Navigate To Mongo Folder
  $ cd /database/mongo

  - Exec Docker Compose Up Command
  $ sudo docker compose up -d

  - Open Bash Inside Docker
  $ sudo docker exec -it <DOCKER CONTAINER ID> bash
```

## Memcached

```bash
  $ sudo apt-get install memcached

  $ sudo nano /etc/memcached.conf
    - Use this to modify memory, port, connection limit and so on

  $ sudo systemctl stop memcached

  $ sudo systemctl start memcached

  $ sudo systemctl restart memcached

  $ sudo systemctl status memcached
```

## Valhalla

```bash
  $ git lfs install
  $ git clone https://huggingface.co/datasets/ghost22bg/valhalla-india
```

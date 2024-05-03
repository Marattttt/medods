# Test assignment for medods

I decided to add a new endpoint /validate which is described in swagger spec and is used to check token status

The project has:

    - a swagger spec at ./swagger.yml

    - Docker file at ./Dockerfile

    - Docker compose which runs both the project and a mongodb image at ./docker-compose.yml

## Running the application

1) First you need to create a .env file (example is provided in .env_example
which uses default configureation from projects config package)
It does not have to include all variables, defaults are provided in config package

2) Then running

```bash

    docker compose up

```

will start all the needed services

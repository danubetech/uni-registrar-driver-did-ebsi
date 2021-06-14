# Dockerfile for universalissuer/revocation-service-driver-revocationregistry2019

FROM node:14.7.0-alpine
# Env
# Set the timezone in docker
# Create Directory for the Container
WORKDIR /usr/src/app
# Only copy the package.json file to work directory
COPY ./package.json .
# Install all Packages
RUN yarn install
# Copy all other source code to work directory
ADD . /usr/src/app
# TypeScript

# Start

CMD [ "yarn", "start" ]
EXPOSE 9080
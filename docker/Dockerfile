# Dockerfile for universalregistrar/driver-did-ebsi

FROM node:14.7.0-alpine
# Env
# Set the timezone in docker
# Create Directory for the Container
WORKDIR /usr/src/app
# Only copy the package.json file to work directory
COPY ./package.json ./
COPY ./tsconfig.json ./
COPY ./yarn.lock ./
COPY ./ ./

# Copy all other source code to work directory
# ADD . /usr/src/app

ENV uniregistrar_driver_did_ebsi_api_operations_preprod='https://api-pilot.ebsi.eu'
ENV uniregistrar_driver_did_ebsi_api_operations_mainnet=
ENV uniregistrar_driver_did_ebsi_api_operations_test=
ENV uniregistrar_driver_did_ebsi_port=9080
ENV uniregistrar_driver_did_ebsi_didRegistry_api_version=v3
ENV uniregistrar_driver_did_ebsi_TIR_api_version=v3
ENV uniregistrar_driver_did_ebsi_ledger_api_version=v3
ENV uniregistrar_driver_did_ebsi_usersOnboarding_api_version=v2
ENV uniregistrar_driver_did_ebsi_authorization_api_version=v2

# Install all Packages
RUN yarn install

# TypeScript
RUN yarn build
# Start

CMD [ "yarn", "start" ]
EXPOSE 9080

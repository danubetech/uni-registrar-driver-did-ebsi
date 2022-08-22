![DIF Logo](https://raw.githubusercontent.com/decentralized-identity/universal-registrar/master/docs/logo-dif.png)

# Universal Registrar Driver: ebsi

This is a [Universal Registrar](https://github.com/decentralized-identity/universal-registrar/) driver for **did:ebsi** identifiers.

## Specifications

- [Decentralized Identifiers](https://w3c.github.io/did-core/)
- [DID Method Specification]

## Build and Run (Docker)

```
docker build -f docker/Dockerfile . -t universalregistrar/driver-did-ebsi:latest
docker run -p 9080:9080 universalregistrar/driver-did-ebsi
```

### DID Registration

- Use the [EBSI authentication token](https://app.preprod.ebsi.eu/users-onboarding/v2) as "secret" token parameter.

```
curl -X POST "http://localhost:9080/1.0/create?method=ebsi" -H "accept: application/json" -H "Content-Type: application/json" -d "{"secret":{"token":"...ey.."} }"
```

Create a private key and then generate a [certificate request](https://en.wikipedia.org/wiki/Certificate_signing_request) from it:
```
> openssl genrsa -out privatekey.pem 2048

> openssl req -new -key privatekey.pem -out certrequest.csr
```

Convert a certificate request into a self signed certificate:
```
> openssl x509 -req -in certrequest.csr -signkey privatekey.pem -out certificate.pem
```
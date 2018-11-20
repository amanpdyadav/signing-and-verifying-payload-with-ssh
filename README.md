# signing-and-verifying-payload-with-ssh
Java GenerateSignature to create a signature from a file containing payload with a public ssh key.
And VerifySignature to validate the signature using private ssh key. 

# Creating certificates

## Generate signed certificate
```
openssl req -x509 -nodes -newkey rsa:2048 -keyout private-key.pem -out public-key.pem
```

## Convert PEM to DER
```
openssl x509 -outform der -in private-key.pem -out private-key.der
```

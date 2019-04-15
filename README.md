# Mock OCSP responder

Mock OCSP responder based on [ocspresponder](https://pypi.org/project/ocspresponder/)
Only major change is the use of ResponderId 'by_name', instead of 'by_key'

Run `docker-compose up -d` to start the responder and 
`openssl ocsp -issuer conf/issuer.crt -cert certs/141811770701420873040773020899829622874.cert.pem -url http://localhost:8080/status -nonce -noverify` 
to test. Output should look something like this: 
````
certs/141811770701420873040773020899829622874.cert.pem: good
        This Update: Sep 13 06:21:09 2018 GMT
        Next Update: Sep 20 06:21:09 2018 GMT

````

## Configuration
See `docker-compose.yml` file on how to add mod_wsgi parameters and run 
`docker-compose exec mock-ocsp mod_wsgi-express start-server --help` for a list of possible configuration values

Generate new OCSP responder certificate with:    
`openssl req -x509 -newkey rsa:2048 -keyout conf/key.pem -out conf/cert.pem -days 3650 -nodes -subj '/CN=MOCK OCSP' -config conf/openssl.conf`
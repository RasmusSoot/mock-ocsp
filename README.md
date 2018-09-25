# Mock OCSP responder

Mock OCSP responder based on [ocspresponder](https://pypi.org/project/ocspresponder/)
Only major change is the use of ResponderId 'by_name', instead of 'by_key'

Run `docker-compose up -d` to start the responder and 
`openssl ocsp -issuer conf/issuer.crt -cert certs/141811770701420873040773020899829622874.cert.pem -url http://localhost:8080/status/ -nonce -noverify` 
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
`openssl req -x509 -newkey rsa:2048 -keyout conf/key.pem -out conf/cert.pem -days 3650 -nodes -subj '/CN=MOCK-OCSP'`

## Modify response
All requests and responses are logged, available at /log/ endpoint
It is possible to modify responses by doing a HTTP POST request /set_status/<certificate serial> with JSON where:

| **Name**        | **Description** |
| :---------------- | :---------- |
| **status** | OCSP response status, String, possible values 'good', 'unknown' and 'revoked' |
| **revoked_at** | Revocation date when status is 'revoked', String with ISO 8601 date. Example value '2012-04-23T18:25:43.511Z' |
| **this_update** | Time delta relative to 'produced_at' in seconds, Integer, defaults to 0 |
| **produced_at** | Time delta relative to now in seconds, Integer, defaults to 0 |
| **next_update** | Time delta in seconds relative to now, Integer, defaults to 60*15 |
| **nonce** | Nonce value, Base64 encoded String |
| **include_nonce** | Controls if nonce is included in response, Boolean, defaults to true |

###Examples
Good, but 30 seconds old:
````
POST /set_status/141811770701420873040773020899829622874 HTTP/1.1
Host: localhost:8080
Content-Type: application/json

{
    "status":"good",
    "produced_at": -30
}
````
Set status revoked:
````
POST /set_status/141811770701420873040773020899829622874 HTTP/1.1
Host: localhost:8080
Content-Type: application/json

{
    "revoked_at": "2012-04-23T18:25:43.511Z",
    "status": "revoked"
}
````
Set invalid nonce:
````
POST /set_status/141811770701420873040773020899829622874 HTTP/1.1
Host: localhost:8080
Content-Type: application/json

{
    "nonce": "iQ6vcsSvcO22badnJp7JGJxiuWo=",
    "status": "good"
}
````
Do not set nonce:
````
POST /set_status/141811770701420873040773020899829622874 HTTP/1.1
Host: localhost:8080
Content-Type: application/json

{
    "include_nonce": false,
    "status": "good"
}
````

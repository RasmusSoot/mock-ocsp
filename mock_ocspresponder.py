import base64
import uuid
from datetime import datetime
from typing import Optional

import dateutil.parser
from bottle import request, HTTPResponse
from ocspbuilder import OCSPResponseBuilder
from ocspresponder import OCSPResponder, CertificateStatus

import mock_responses
import monkeypatch

OCSPResponseBuilder.build = monkeypatch.build
ISSUER_CERT = 'conf/issuer.crt'
OCSP_CERT = 'conf/cert.pem'
OCSP_KEY = 'conf/key.pem'

request_response_log = {}


class ConfiguraleOcspResponder(OCSPResponder):

    def _route(self):
        self._app.get('/', callback=self._handle_root)
        self._app.get('/status/<request_data>', callback=self._handle_get)
        self._app.post('/status/', callback=self._handle_post)
        self._app.get('/log/', callback=self._handle_log)
        self._app.post('/set_status/<serialnumber>', callback=self._set_status)

    def _handle_get(self, request_data):
        uid = uuid.uuid4()
        request_response_log[uid] = {'request': request_data}
        response = OCSPResponder._handle_get(self, request_data)
        request_response_log[uid]['response'] = response
        return response

    def _set_status(self, serialnumber):
        mock_responses.responses[int(serialnumber)] = request.json
        return HTTPResponse(
            status=200,
            body=mock_responses.responses
        )

    def _handle_post(self):
        """
        An OCSP POST request contains the DER encoded OCSP request in the HTTP
        request body.
        """
        der = request.body.read()
        uid = uuid.uuid4()
        request_response_log[uid] = {'request': base64.b64encode(der)}
        ocsp_request = self._parse_ocsp_request(der)
        response = self._build_http_response(ocsp_request)
        request_response_log[uid]['response'] = base64.b64encode(response.body)
        return response

    def _handle_log(self):
        return HTTPResponse(
            status=200,
            body=str(request_response_log)
        )

    def serve(self, port=8080, debug=False):
        self._app.run(host='0.0.0.0', port=port, debug=debug)


def validate(serial: int) -> (CertificateStatus, Optional[datetime]):
    try:
        status = mock_responses.responses[serial]['status']
        if (status == 'good'):
            return (CertificateStatus.good, None)
        elif status == 'unknown':
            return (CertificateStatus.unknown, None)
        elif status == 'revoked':
            return (CertificateStatus.revoked, dateutil.parser.parse(mock_responses.responses[serial]['revoked_at']))
    except KeyError:
        return (CertificateStatus.good, None)


def get_cert(serial: int) -> str:
    """
    Assume the certificates are stored in the ``certs`` directory with the
    serial as base filename.
    """
    with open('certs/%s.cert.pem' % serial, 'r') as f:
        return f.read().strip()


app = ConfiguraleOcspResponder(
    ISSUER_CERT, OCSP_CERT, OCSP_KEY,
    validate_func=validate,
    cert_retrieve_func=get_cert,
)

if __name__ == "__main__":
    app.serve(port=8080, debug=True)

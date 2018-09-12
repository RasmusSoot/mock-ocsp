from datetime import datetime
from typing import Optional

from ocspbuilder import OCSPResponseBuilder
from ocspresponder import OCSPResponder, CertificateStatus

import monkeypatch

OCSPResponseBuilder.build = monkeypatch.build
OCSPResponder.serve = monkeypatch.serve

ISSUER_CERT = 'conf/issuer.crt'
OCSP_CERT = 'conf/cert.pem'
OCSP_KEY = 'conf/key.pem'


def validate(serial: int) -> (CertificateStatus, Optional[datetime]):
    return (CertificateStatus.good, None)


def get_cert(serial: int) -> str:
    """
    Assume the certificates are stored in the ``certs`` directory with the
    serial as base filename.
    """
    with open('certs/%s.cert.pem' % serial, 'r') as f:
        return f.read().strip()


app = OCSPResponder(
    ISSUER_CERT, OCSP_CERT, OCSP_KEY,
    validate_func=validate,
    cert_retrieve_func=get_cert,
)

if __name__ == "__main__":
    app.serve(port=8080, debug=True)

from __future__ import unicode_literals, division, absolute_import, print_function

import inspect
import logging
import re
import textwrap
from datetime import datetime, timedelta

from asn1crypto import x509, keys, core, ocsp
from asn1crypto.util import timezone
from oscrypto import asymmetric


def build(self, responder_private_key=None, responder_certificate=None):
    """
    Validates the request information, constructs the ASN.1 structure and
    signs it.

    The responder_private_key and responder_certificate parameters are only
    required if the response_status is "successful".

    :param responder_private_key:
        An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
        object for the private key to sign the response with

    :param responder_certificate:
        An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
        object of the certificate associated with the private key

    :return:
        An asn1crypto.ocsp.OCSPResponse object of the response
    """
    if self._response_status != 'successful':
        return ocsp.OCSPResponse({
            'response_status': self._response_status
        })

    is_oscrypto = isinstance(responder_private_key, asymmetric.PrivateKey)
    if not isinstance(responder_private_key, keys.PrivateKeyInfo) and not is_oscrypto:
        raise TypeError(_pretty_message(
            '''
            responder_private_key must be an instance of
            asn1crypto.keys.PrivateKeyInfo or
            oscrypto.asymmetric.PrivateKey, not %s
            ''',
            _type_name(responder_private_key)
        ))

    cert_is_oscrypto = isinstance(responder_certificate, asymmetric.Certificate)
    if not isinstance(responder_certificate, x509.Certificate) and not cert_is_oscrypto:
        raise TypeError(_pretty_message(
            '''
            responder_certificate must be an instance of
            asn1crypto.x509.Certificate or
            oscrypto.asymmetric.Certificate, not %s
            ''',
            _type_name(responder_certificate)
        ))

    if cert_is_oscrypto:
        responder_certificate = responder_certificate.asn1

    if self._certificate is None:
        raise ValueError(_pretty_message(
            '''
            certificate must be set if the response_status is
            "successful"
            '''
        ))
    if self._certificate_status is None:
        raise ValueError(_pretty_message(
            '''
            certificate_status must be set if the response_status is
            "successful"
            '''
        ))

    def _make_extension(name, value):
        return {
            'extn_id': name,
            'critical': False,
            'extn_value': value
        }

    response_data_extensions = []
    single_response_extensions = []

    for name, value in self._response_data_extensions.items():
        response_data_extensions.append(_make_extension(name, value))
    if self._nonce:
        response_data_extensions.append(
            _make_extension('nonce', self._nonce)
        )

    if not response_data_extensions:
        response_data_extensions = None

    for name, value in self._single_response_extensions.items():
        single_response_extensions.append(_make_extension(name, value))

    if self._certificate_issuer:
        single_response_extensions.append(
            _make_extension(
                'certificate_issuer',
                [
                    x509.GeneralName(
                        name='directory_name',
                        value=self._certificate_issuer.subject
                    )
                ]
            )
        )

    if not single_response_extensions:
        single_response_extensions = None

    responder_key_hash = getattr(responder_certificate.public_key, self._key_hash_algo)

    if self._certificate_status == 'good':
        cert_status = ocsp.CertStatus(
            name='good',
            value=core.Null()
        )
    elif self._certificate_status == 'unknown':
        cert_status = ocsp.CertStatus(
            name='unknown',
            value=core.Null()
        )
    else:
        status = self._certificate_status
        reason = status if status != 'revoked' else 'unspecified'
        cert_status = ocsp.CertStatus(
            name='revoked',
            value={
                'revocation_time': self._revocation_date,
                'revocation_reason': reason,
            }
        )

    issuer = self._certificate_issuer if self._certificate_issuer else responder_certificate
    if issuer.subject != self._certificate.issuer:
        raise ValueError(_pretty_message(
            '''
            responder_certificate does not appear to be the issuer for
            the certificate. Perhaps set the .certificate_issuer attribute?
            '''
        ))

    produced_at = datetime.now(timezone.utc)

    if self._this_update is None:
        self._this_update = produced_at

    if self._next_update is None:
        self._next_update = self._this_update + timedelta(days=7)
    name = x509.Name.build({"common_name": responder_certificate.subject.native['common_name']})
    str(
        name)  # TODO: this is mandatory, or asn1crypto.core.Sequence.__setitem__ considers it invalid @ "invalid_value = new_value.chosen.contents is None"
    response_data = ocsp.ResponseData({
        'responder_id': ocsp.ResponderId(name='by_name', value=name),
        'produced_at': produced_at,
        'responses': [
            {
                'cert_id': {
                    'hash_algorithm': {
                        'algorithm': self._key_hash_algo
                    },
                    'issuer_name_hash': getattr(self._certificate.issuer, self._key_hash_algo),
                    'issuer_key_hash': getattr(issuer.public_key, self._key_hash_algo),
                    'serial_number': self._certificate.serial_number,
                },
                'cert_status': cert_status,
                'this_update': self._this_update,
                'next_update': self._next_update,
                'single_extensions': single_response_extensions
            }
        ],
        'response_extensions': response_data_extensions
    })

    signature_algo = responder_private_key.algorithm
    if signature_algo == 'ec':
        signature_algo = 'ecdsa'

    signature_algorithm_id = '%s_%s' % (self._hash_algo, signature_algo)

    if responder_private_key.algorithm == 'rsa':
        sign_func = asymmetric.rsa_pkcs1v15_sign
    elif responder_private_key.algorithm == 'dsa':
        sign_func = asymmetric.dsa_sign
    elif responder_private_key.algorithm == 'ec':
        sign_func = asymmetric.ecdsa_sign

    if not is_oscrypto:
        responder_private_key = asymmetric.load_private_key(responder_private_key)
    signature_bytes = sign_func(responder_private_key, response_data.dump(), self._hash_algo)
    certs = None
    if self._certificate_issuer:
        certs = [responder_certificate]

    return ocsp.OCSPResponse({
        'response_status': self._response_status,
        'response_bytes': {
            'response_type': 'basic_ocsp_response',
            'response': {
                'tbs_response_data': response_data,
                'signature_algorithm': {'algorithm': signature_algorithm_id},
                'signature': signature_bytes,
                'certs': certs
            }
        }
    })


def _pretty_message(string, *params):
    """
    Takes a multi-line string and does the following:

     - dedents
     - converts newlines with text before and after into a single line
     - strips leading and trailing whitespace

    :param string:
        The string to format

    :param *params:
        Params to interpolate into the string

    :return:
        The formatted string
    """

    output = textwrap.dedent(string)

    # Unwrap lines, taking into account bulleted lists, ordered lists and
    # underlines consisting of = signs
    if output.find('\n') != -1:
        output = re.sub('(?<=\\S)\n(?=[^ \n\t\\d\\*\\-=])', ' ', output)

    if params:
        output = output % params

    output = output.strip()

    return output


def _type_name(value):
    """
    :param value:
        A value to get the object name of

    :return:
        A unicode string of the object name
    """

    if inspect.isclass(value):
        cls = value
    else:
        cls = value.__class__
    if cls.__module__ in set(['builtins', '__builtin__']):
        return cls.__name__
    return '%s.%s' % (cls.__module__, cls.__name__)


logger = logging.getLogger(__name__)


def serve(self, port=8080, debug=False):
    logger.info('Launching %sserver on port %d', 'debug' if debug else '', port)
    self._app.run(host='0.0.0.0', port=port, debug=debug)

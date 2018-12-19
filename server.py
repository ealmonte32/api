import os
import cfssl
import redis
from flask import Flask, request, jsonify

__author__ = "Viktor Petersson"
__version__ = "0.1.0"

API_PREFIX = '/api/v0.1'
CFSSL_SERVER = os.getenv('CFSSL_SERVER', '127.0.0.1')
CFSSL_PORT = int(os.getenv('CFSSL_PORT', 8888))

app = Flask(__name__)
r = redis.Redis(
        host=os.getenv('REDIS_SERVER', '127.0.0.1'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        db=0
        )


@app.route('/')
def root():
    return 'Nothing to see here. Go away!'


@app.route('/v0.1/ca', methods=['GET'])
def root_ca():
    """
    Returns the root certificate.
    """
    # Try to use cache for cert retrieval
    if r.get('ca_cert'):
        return jsonify({
            'ca': r.get('ca_cert').decode(),
            })

    print('Fetching root cert from CA...')
    cf = cfssl.cfssl.CFSSL(
            host=CFSSL_SERVER,
            port=CFSSL_PORT,
            ssl=False
    )

    ca = cf.info(label='primary')['certificate']
    r.set('ca_cert', ca)
    return jsonify({'ca': ca})


@app.route('/v0.1/cert-db/<device_uuid>', methods=['GET'])
def get_device_cert(device_uuid):
    """
    Retrieves the certificate for a given device.
    """
    if r.get(device_uuid):
        return jsonify({
            'crt': r.get(device_uuid).decode(),
           })
    else:
        return 'Device not found.', 404


@app.route('/v0.1/sign/<device_uuid>', methods=['POST'])
def sign_device_cert(device_uuid):
    """
    Signs a certificate.
    """

    # Basic check to only allow signing of certificates
    # under the domain d.wott.io
    if not device_uuid.endswith('.d.wott.io'):
        return 'Invalid device uuid', 400

    content = request.get_json()
    if not content:
        return 'Invalid payload.', 400

    if not content.get('csr'):
        return 'Missing key "csr" in payload.', 400

    cf = cfssl.cfssl.CFSSL(
            host=CFSSL_SERVER,
            port=CFSSL_PORT,
            ssl=False
    )

    certificate = cf.sign(
            certificate_request=content['csr'],
            hosts=['{}'.format(device_uuid)]
            )

    r.set(device_uuid, certificate)

    return jsonify({
        'crt': certificate,
        })

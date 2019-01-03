import os
import cfssl
import redis
import uuid
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


@app.route('/v0.1/generate-id', methods=['GET'])
def generate_device_id():
    """
    Returns a random new device ID.
    We're using Redis for this for now.
    This needs to be moved to a proper database later.

    There's also a potential race condition here because
    two devices could the same device_id before the CSR has
    been signed and hence not locked.
    """

    cert_in_use = True
    while cert_in_use:
        device_id = '{}.d.wott.local'.format(uuid.uuid4().hex)
        if not r.get(device_id):
            cert_in_use = False

    return jsonify({'device_id': device_id})


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


@app.route('/renew/v0.1/sign', methods=['POST'])
def renew_device_cert():
    return ' '.join(request.headers)


@app.route('/v0.1/sign', methods=['POST'])
def sign_device_cert():
    """
    Signs a certificate.
    """

    content = request.get_json()
    if not content:
        return 'Invalid payload.', 400

    if not content.get('csr'):
        return 'Missing key "csr" in payload.', 400

    if not content.get('device_id'):
        return 'Missing key "device_id" in payload.', 400

    # Basic check to only allow signing of certificates
    # under the domain d.wott.io
    if not content['device_id'].endswith('.d.wott.local'):
        return 'Invalid device uuid', 400

    # Only allow certificate to be signed once
    if r.get(content['device_id']):
        return 'Certificate already exist.', 400

    cf = cfssl.cfssl.CFSSL(
            host=CFSSL_SERVER,
            port=CFSSL_PORT,
            ssl=False
    )

    certificate = cf.sign(
            certificate_request=content['csr'],
            hosts=['{}'.format(content['device_id'])]
            )

    r.set(content['device_id'], certificate)

    return jsonify({
        'crt': certificate,
        })

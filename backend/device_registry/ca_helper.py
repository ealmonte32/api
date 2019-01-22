import cfssl
import logging

from backend import settings
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID


logger = logging.getLogger(__name__)


def get_certificate_expiration_date(certificate):
    """
    Returns the expiration date of the certificate.
    """

    cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
    return cert.not_valid_after


def sign_csr(csr, hostname):
    """
    Takes a CSR and signs it on the CA server.
    """
    cf = cfssl.cfssl.CFSSL(
        host=settings.CFSSL_SERVER,
        port=settings.CFSSL_PORT,
        ssl=False
    )

    return cf.sign(
        certificate_request=csr,
        hosts=['{}'.format(hostname)]
    )


def csr_is_valid(csr=None, device_id=None):
    """
    Parse the submitted CSR and ensure that it is both valid
    and falls in the acceptable domain prefix(es).
    """
    try:
        parse_csr = x509.load_pem_x509_csr(csr.encode(), default_backend())
    except TypeError:
        return False

    csr_common_name = parse_csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(csr_common_name) > 1:
            logging.error('[CSR] More than one Common Name in the CSR.')
            return False

    for common_name in csr_common_name:
        if not common_name.value.endswith(settings.COMMON_NAME_PREFIX):
            logging.error('[CSR] Common Name ({}) does not match the signing policy.'.format(common_name.value))
            return False
        device_common_name = common_name.value

    try:
        csr_subject_alt_name = parse_csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
                x509.DNSName)
    except x509.extensions.ExtensionNotFound:
        logging.error('[CSR] Expected Subject Alt Name, but it was not present.')
        return False

    if len(csr_subject_alt_name) > 1:
            logging.error('[CSR] More than one Subject Alt Name in the CSR.')
            return False

    for subject_alt_name in csr_subject_alt_name:
        if not subject_alt_name.endswith(settings.COMMON_NAME_PREFIX):
            logging.error('[CSR] Subject Alt Name ({}) does not match the signing policy.'.format(subject_alt_name))
            return False
        device_subject_alt_name = subject_alt_name

    if not device_subject_alt_name == device_common_name:
        logging.error('[CSR] Subject Alt Name ({}) does not match Common Name ({}).'.format(
            device_subject_alt_name,
            device_common_name)
        )
        return False

    if not device_common_name == device_id:
        logging.error('[CSR] Common Name ({}) does not match device_id ({}).'.format(
            device_common_name,
            device_id
        ))
        return False


    return True

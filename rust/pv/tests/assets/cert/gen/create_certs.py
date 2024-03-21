#!/bin/env python3
import datetime
import os.path
from enum import Enum

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

ONE_DAY = datetime.timedelta(1, 0, 0)


def createEcKeyPair(curve=ec.SECP521R1):
    return ec.generate_private_key(curve=curve, backend=default_backend())


def createRSAKeyPair(size=4096):
    return rsa.generate_private_key(
        public_exponent=65537, key_size=size, backend=default_backend()
    )


def createCRL(
    pkey, issuer, serial_numbers=None, last_update=None, next_update=None, authid=True
):
    serial_numbers = [333] if serial_numbers is None else serial_numbers
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer)
    last_update = last_update or datetime.datetime.today() - 10 * ONE_DAY
    next_update = next_update or datetime.datetime.today() + 365 * 365 * ONE_DAY
    builder = builder.last_update(last_update)
    builder = builder.next_update(next_update)
    for sn in serial_numbers:
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(sn)
            .revocation_date(
                datetime.datetime.today() - ONE_DAY,
            )
            .build(default_backend())
        )
        builder = builder.add_revoked_certificate(revoked_cert)
    if authid:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(pkey.public_key()),
            critical=False,
        )
    crl = builder.sign(
        private_key=pkey, algorithm=hashes.SHA512(), backend=default_backend()
    )
    return crl


class CertType(Enum):
    ROOT_CA = 1
    INTER_CA = 2
    SIGNING_CERT = 3
    HOST_CERT = 4


def createCert(
    pkey,
    subject,
    crl_uri,
    issuer_crt=None,
    issuer_pkey=None,
    t=CertType.ROOT_CA,
    not_before=None,
    not_after=None,
    pub_key=None,
):
    sha = hashes.SHA256
    not_before = not_before or datetime.datetime.utcnow()
    not_after = not_after or datetime.datetime.utcnow() + datetime.timedelta(
        days=365 * 365
    )
    crl_dp = None
    if crl_uri is not None:
        crl_dp = x509.DistributionPoint(
            [x509.UniformResourceIdentifier(crl_uri)],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
        )
    cert_builder = x509.CertificateBuilder().subject_name(subject)
    if t == CertType.ROOT_CA:
        cert_builder = cert_builder.issuer_name(subject)
        issuer_pub_key = pkey.public_key()
    else:
        cert_builder = cert_builder.issuer_name(issuer_crt.subject)
        issuer_pub_key = issuer_crt.public_key()
    if pub_key is None:
        pub_key = pkey.public_key()

    cert_builder = (
        cert_builder.public_key(pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if crl_dp is not None:
        cert_builder = cert_builder.add_extension(
            x509.CRLDistributionPoints([crl_dp]),
            critical=False,
        )

    if t == CertType.ROOT_CA:
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=True,
                crl_sign=True,
            ),
            critical=True,
        )
    elif t == CertType.INTER_CA:
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=True,
                crl_sign=True,
            ),
            critical=True,
        )
    elif t == CertType.SIGNING_CERT:
        cert_builder = (
            cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                    key_cert_sign=False,
                    crl_sign=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]),
                critical=False,
            )
        )
    else:
        sha = hashes.SHA512
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=True,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False,
            ),
            critical=True,
        )

    cert_builder = cert_builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub_key),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(pkey.public_key()),
        critical=False,
    )
    return cert_builder.sign(issuer_pkey, sha(), default_backend())


def getPrivKey(path, create_priv_key):
    pkey = None
    if os.path.isfile(path):
        with open(path, "rb") as f:
            pkey = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    if not pkey:
        pkey = create_priv_key()
        with open(path, "wb") as f:
            f.write(
                pkey.private_bytes(
                    serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    return pkey


if __name__ == "__main__":
    MOCKUP_CRL_DIST = ""

    # create root CA
    root_ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Armonk"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Root CA"),
        ]
    )
    root_ca_pkey = getPrivKey("root_ca.key", createRSAKeyPair)
    root_ca_crl = createCRL(root_ca_pkey, root_ca_subject, [333])

    root_ca_crt = createCert(
        pkey=root_ca_pkey,
        subject=root_ca_subject,
        issuer_pkey=root_ca_pkey,
        crl_uri=None,
        t=CertType.ROOT_CA,
    )

    fake_root_ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Armonk"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Root CA"),
        ]
    )
    fake_root_ca_pkey = getPrivKey("fake_root_ca.key", createRSAKeyPair)
    fake_root_ca_crl = createCRL(fake_root_ca_pkey, fake_root_ca_subject, [333])
    fake_root_ca_valid_crl = createCRL(root_ca_pkey, fake_root_ca_subject, [333])
    fake_root_ca_crt = createCert(
        pkey=fake_root_ca_pkey,
        subject=fake_root_ca_subject,
        issuer_pkey=fake_root_ca_pkey,
        crl_uri=None,
        t=CertType.ROOT_CA,
    )

    fake_root_ca_crt = createCert(
        pkey=fake_root_ca_pkey,
        subject=fake_root_ca_subject,
        issuer_pkey=fake_root_ca_pkey,
        crl_uri=None,
        t=CertType.ROOT_CA,
    )

    # create intermediate CA
    inter_ca_pkey = getPrivKey("inter_ca.key", createRSAKeyPair)
    inter_ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Armonk"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Intermediate CA"
            ),
        ]
    )

    inter_ca_crt = createCert(
        pkey=inter_ca_pkey,
        subject=inter_ca_subject,
        issuer_crt=root_ca_crt,
        issuer_pkey=root_ca_pkey,
        crl_uri=MOCKUP_CRL_DIST + "root_ca.crl",
        t=CertType.INTER_CA,
    )

    fake_inter_ca_pkey = getPrivKey("fake_inter_ca.key", createRSAKeyPair)
    fake_inter_ca_crt = createCert(
        pkey=fake_inter_ca_pkey,
        subject=inter_ca_subject,
        issuer_crt=fake_root_ca_crt,
        issuer_pkey=fake_root_ca_pkey,
        crl_uri=MOCKUP_CRL_DIST + "fake_root_ca.crl",
        t=CertType.INTER_CA,
    )
    fake_inter_ca_crl = createCRL(fake_inter_ca_pkey, inter_ca_subject, [444])

    # create ibm certificate
    ibm_pkey = getPrivKey("ibm.key", createRSAKeyPair)
    ibm_subject_poughkeepsie = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Poughkeepsie"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Host Key Signing Service"
            ),
        ]
    )
    ibm_pougkeepsie_crt = createCert(
        pkey=ibm_pkey,
        subject=ibm_subject_poughkeepsie,
        issuer_crt=inter_ca_crt,
        issuer_pkey=inter_ca_pkey,
        crl_uri=MOCKUP_CRL_DIST + "inter_ca.crl",
        t=CertType.SIGNING_CERT,
    )

    ibm_subject_armonk = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Armonk"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Host Key Signing Service"
            ),
        ]
    )
    ibm_armonk_crt = createCert(
        pkey=ibm_pkey,
        subject=ibm_subject_armonk,
        issuer_crt=inter_ca_crt,
        issuer_pkey=inter_ca_pkey,
        crl_uri=MOCKUP_CRL_DIST + "inter_ca.crl",
        t=CertType.SIGNING_CERT,
    )
    ibm_expired_crt = createCert(
        pkey=ibm_pkey,
        subject=ibm_subject_poughkeepsie,
        issuer_crt=inter_ca_crt,
        issuer_pkey=inter_ca_pkey,
        crl_uri=MOCKUP_CRL_DIST + "inter_ca.crl",
        t=CertType.SIGNING_CERT,
        not_before=datetime.datetime.today() - 2 * 365 * ONE_DAY,
        not_after=datetime.datetime.today() - 1 * 365 * ONE_DAY,
    )

    # create revoked ibm certificate
    ibm_rev_pkey = getPrivKey("ibm.key", createRSAKeyPair)
    ibm_rev_crt = createCert(
        pkey=ibm_rev_pkey,
        subject=ibm_subject_poughkeepsie,
        issuer_crt=inter_ca_crt,
        issuer_pkey=inter_ca_pkey,
        crl_uri=MOCKUP_CRL_DIST + "inter_ca.crl",
        t=CertType.SIGNING_CERT,
    )

    # create inter CLRs
    inter_ca_crl = createCRL(
        inter_ca_pkey, inter_ca_subject, [444, ibm_rev_crt.serial_number]
    )
    inter_ca_invalid_signer_crl = createCRL(root_ca_pkey, inter_ca_subject, [444])
    inter_ca_invalid_date_crl = createCRL(
        inter_ca_pkey,
        inter_ca_subject,
        [444],
        last_update=datetime.datetime.today() - 2 * ONE_DAY,
        next_update=datetime.datetime.today() - 1 * ONE_DAY,
    )

    # create signing key using wrong OU in subject
    ibm_wrong_subject_pkey = getPrivKey("ibm_wrong_subject.key", createRSAKeyPair)
    ibm_wrong_subject_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Poughkeepsie"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, u"Key Signing Service Invalid"
            ),
        ]
    )
    ibm_wrong_subject_crl = createCRL(
        ibm_wrong_subject_pkey, ibm_wrong_subject_subject, [555]
    )
    ibm_wrong_subject_crt = createCert(
        pkey=ibm_wrong_subject_pkey,
        subject=ibm_wrong_subject_subject,
        issuer_crt=inter_ca_crt,
        issuer_pkey=inter_ca_pkey,
        crl_uri=MOCKUP_CRL_DIST + "inter_ca.crl",
        t=CertType.SIGNING_CERT,
    )

    fake_ibm_pkey = getPrivKey("fake_ibm.key", createRSAKeyPair)
    fake_ibm_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Poughkeepsie"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Host Key Signing Service"
            ),
        ]
    )
    fake_ibm_crl = createCRL(fake_ibm_pkey, fake_ibm_subject, [555])
    fake_ibm_crt = createCert(
        pkey=fake_ibm_pkey,
        subject=fake_ibm_subject,
        issuer_crt=fake_root_ca_crt,
        issuer_pkey=fake_root_ca_pkey,
        crl_uri=MOCKUP_CRL_DIST + "fake_root_ca.crl",
        t=CertType.SIGNING_CERT,
    )

    def host_subj():
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME,
                    u"International Business Machines Corporation",
                ),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, u"International Business Machines Corporation"
                ),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Armonk"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Host Key"),
            ]
        )

    # create host certificate
    host_pkey = getPrivKey("host.key", createEcKeyPair)
    host_subject = host_subj()
    host_crt = createCert(
        pkey=host_pkey,
        subject=host_subject,
        issuer_crt=ibm_pougkeepsie_crt,
        issuer_pkey=ibm_pkey,
        crl_uri=MOCKUP_CRL_DIST + "ibm.crl",
        t=CertType.HOST_CERT,
    )
    host_crt_expired = createCert(
        pkey=host_pkey,
        subject=host_subject,
        issuer_crt=ibm_pougkeepsie_crt,
        issuer_pkey=ibm_pkey,
        crl_uri=MOCKUP_CRL_DIST + "ibm.crl",
        t=CertType.HOST_CERT,
        not_before=datetime.datetime.today() - 2 * 365 * ONE_DAY,
        not_after=datetime.datetime.today() - 1 * 365 * ONE_DAY,
    )
    host_uri_na_crt = createCert(
        pkey=host_pkey,
        subject=host_subject,
        issuer_crt=ibm_pougkeepsie_crt,
        issuer_pkey=ibm_pkey,
        crl_uri=MOCKUP_CRL_DIST + "notavailable",
        t=CertType.HOST_CERT,
    )

    host_pkey = getPrivKey("host.key", createEcKeyPair)
    host_subject = host_subj()
    host_crt = createCert(
        pkey=host_pkey,
        subject=host_subject,
        issuer_crt=ibm_pougkeepsie_crt,
        issuer_pkey=ibm_pkey,
        crl_uri=MOCKUP_CRL_DIST + "ibm.crl",
        t=CertType.HOST_CERT,
    )

    host_rev_pkey = getPrivKey("host_rev.key", createEcKeyPair)
    host_rev_subject = host_subj()
    host_rev_crt = createCert(
        pkey=host_rev_pkey,
        subject=host_rev_subject,
        issuer_crt=ibm_pougkeepsie_crt,
        issuer_pkey=ibm_pkey,
        crl_uri=MOCKUP_CRL_DIST + "ibm.crl",
        t=CertType.HOST_CERT,
    )

    # some IBM revocation lists
    ibm_poughkeepsie_crl = createCRL(
        ibm_pkey, ibm_subject_poughkeepsie, [555, host_rev_crt.serial_number]
    )
    ibm_armonk_crl = createCRL(
        ibm_pkey, ibm_subject_armonk, [555, host_rev_crt.serial_number]
    )

    ibm_outdated_early_crl = createCRL(
        ibm_pkey,
        ibm_subject_poughkeepsie,
        [],
        last_update=datetime.datetime.today() + 1000 * 365 * ONE_DAY,
        next_update=datetime.datetime.today() + 1001 * 365 * ONE_DAY,
    )
    ibm_outdated_late_crl = createCRL(
        ibm_pkey,
        ibm_subject_poughkeepsie,
        [],
        last_update=datetime.datetime.today() - 2 * 365 * ONE_DAY,
        next_update=datetime.datetime.today() - 1 * 365 * ONE_DAY,
    )
    ibm_wrong_issuer_priv_key_crl = createCRL(
        ibm_pkey, inter_ca_subject, [], authid=False
    )
    ibm_invalid_hash_crl = createCRL(
        inter_ca_pkey,
        ibm_subject_poughkeepsie,
        [555, host_crt.serial_number],
        authid=False,
    )

    # create host certificate issued by a non-valid signing key
    host_invalid_signing_key_pkey = getPrivKey(
        "host_invalid_signing_key.key", createEcKeyPair
    )
    host_invalid_signing_key_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Armonk"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Host Key"),
        ]
    )
    host_invalid_signing_key_crt = createCert(
        pkey=host_invalid_signing_key_pkey,
        subject=host_invalid_signing_key_subject,
        issuer_crt=ibm_wrong_subject_crt,
        issuer_pkey=ibm_wrong_subject_pkey,
        crl_uri=MOCKUP_CRL_DIST + "ibm_wrong_subject.crl",
        t=CertType.HOST_CERT,
    )

    host2_pkey = getPrivKey("host2.key", createEcKeyPair)
    host2_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Armonk"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Host Key"),
        ]
    )
    host2_crt = createCert(
        pkey=host2_pkey,
        subject=host2_subject,
        issuer_crt=ibm_pougkeepsie_crt,
        issuer_pkey=ibm_pkey,
        crl_uri=MOCKUP_CRL_DIST + "ibm.crl",
        t=CertType.HOST_CERT,
    )

    host_armonk_pkey = getPrivKey("host.key", createEcKeyPair)
    host_armonk_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Armonk"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Host Key"),
        ]
    )
    host_armonk_crt = createCert(
        pkey=host_armonk_pkey,
        subject=host_armonk_subject,
        issuer_crt=ibm_armonk_crt,
        issuer_pkey=ibm_pkey,
        crl_uri=MOCKUP_CRL_DIST + "ibm_armonk.crl",
        t=CertType.HOST_CERT,
    )

    fake_host_pkey = getPrivKey("fake_host.key", createEcKeyPair)
    fake_host_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"International Business Machines Corporation",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u"International Business Machines Corporation"
            ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Armonk"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Z Host Key"),
        ]
    )
    fake_host_crt = createCert(
        pkey=fake_host_pkey,
        subject=fake_host_subject,
        issuer_crt=fake_ibm_crt,
        issuer_pkey=fake_ibm_pkey,
        crl_uri=MOCKUP_CRL_DIST + "fake_ibm.crt",
        t=CertType.HOST_CERT,
    )
    # TODO DER chain

    # store CA
    with open("root_ca.crt", "wb") as f:
        f.write(root_ca_crt.public_bytes(serialization.Encoding.PEM))
    with open("root_ca.crl", "wb") as f:
        f.write(root_ca_crl.public_bytes(serialization.Encoding.PEM))
    with open("root_ca.chained.crt", "wb") as f:
        f.write(root_ca_crt.public_bytes(serialization.Encoding.PEM))
        f.write(root_ca_crl.public_bytes(serialization.Encoding.PEM))

    with open("fake_root_ca.crt", "wb") as f:
        f.write(fake_root_ca_crt.public_bytes(serialization.Encoding.PEM))
    with open("fake_root_ca.crl", "wb") as f:
        f.write(fake_root_ca_crl.public_bytes(serialization.Encoding.PEM))
    with open("fake_root_ca_valid.crl", "wb") as f:
        f.write(fake_root_ca_valid_crl.public_bytes(serialization.Encoding.PEM))

    with open("inter_ca.crt", "wb") as f:
        f.write(inter_ca_crt.public_bytes(serialization.Encoding.PEM))
    with open("inter_ca.crl", "wb") as f:
        f.write(inter_ca_crl.public_bytes(serialization.Encoding.PEM))
    with open("inter_ca.invalid_date.crl", "wb") as f:
        f.write(inter_ca_invalid_date_crl.public_bytes(serialization.Encoding.PEM))
    with open("inter_ca.invalid_signer.crl", "wb") as f:
        f.write(inter_ca_invalid_signer_crl.public_bytes(serialization.Encoding.PEM))
    with open("inter_ca.chained.crt", "wb") as f:
        f.write(inter_ca_crt.public_bytes(serialization.Encoding.PEM))
        f.write(inter_ca_crl.public_bytes(serialization.Encoding.PEM))
    with open("fake_inter_ca.crt", "wb") as f:
        f.write(fake_inter_ca_crt.public_bytes(serialization.Encoding.PEM))
    with open("fake_inter_ca.crl", "wb") as f:
        f.write(fake_inter_ca_crl.public_bytes(serialization.Encoding.PEM))

    # store IBM
    with open("ibm.crt", "wb") as f:
        f.write(ibm_pougkeepsie_crt.public_bytes(serialization.Encoding.PEM))
    with open("ibm_armonk.crt", "wb") as f:
        f.write(ibm_armonk_crt.public_bytes(serialization.Encoding.PEM))
    with open("ibm_rev.crt", "wb") as f:
        f.write(ibm_rev_crt.public_bytes(serialization.Encoding.PEM))
    with open("ibm_expired.crt", "wb") as f:
        f.write(ibm_expired_crt.public_bytes(serialization.Encoding.PEM))
    with open("ibm.crl", "wb") as f:
        f.write(ibm_poughkeepsie_crl.public_bytes(serialization.Encoding.PEM))
    with open("ibm_armonk.crl", "wb") as f:
        f.write(ibm_armonk_crl.public_bytes(serialization.Encoding.PEM))
    with open("ibm.chained.crt", "wb") as f:
        f.write(ibm_poughkeepsie_crl.public_bytes(serialization.Encoding.PEM))
        f.write(ibm_pougkeepsie_crt.public_bytes(serialization.Encoding.PEM))
    with open("ibm_outdated_early.crl", "wb") as f:
        f.write(ibm_outdated_early_crl.public_bytes(serialization.Encoding.PEM))
    with open("ibm_outdated_late.crl", "wb") as f:
        f.write(ibm_outdated_late_crl.public_bytes(serialization.Encoding.PEM))
    with open("ibm_wrong_issuer.crl", "wb") as f:
        f.write(ibm_wrong_issuer_priv_key_crl.public_bytes(serialization.Encoding.PEM))
    with open("ibm_invalid_hash.crl", "wb") as f:
        f.write(ibm_invalid_hash_crl.public_bytes(serialization.Encoding.PEM))
    with open("ibm_wrong_subject.crt", "wb") as f:
        f.write(ibm_wrong_subject_crt.public_bytes(serialization.Encoding.PEM))
    with open("ibm_wrong_subject.crl", "wb") as f:
        f.write(ibm_wrong_subject_crl.public_bytes(serialization.Encoding.PEM))

    with open("fake_ibm.crt", "wb") as f:
        f.write(fake_ibm_crt.public_bytes(serialization.Encoding.PEM))
    with open("fake_ibm.crl", "wb") as f:
        f.write(fake_ibm_crl.public_bytes(serialization.Encoding.PEM))

    # store host
    with open("host.crt", "wb") as f:
        f.write(host_crt.public_bytes(serialization.Encoding.PEM))
    with open("host_uri_na.crt", "wb") as f:
        f.write(host_uri_na_crt.public_bytes(serialization.Encoding.PEM))

    # store host key issued by a signing key using the wrong subject OU
    with open("host_invalid_signing_key.crt", "wb") as f:
        f.write(host_invalid_signing_key_crt.public_bytes(serialization.Encoding.PEM))

    # store revoked host
    with open("host_rev.crt", "wb") as f:
        f.write(host_rev_crt.public_bytes(serialization.Encoding.PEM))

    # store host2
    with open("host2.crt", "wb") as f:
        f.write(host2_crt.public_bytes(serialization.Encoding.PEM))

    # store host_armonk
    with open("host_armonk.crt", "wb") as f:
        f.write(host_armonk_crt.public_bytes(serialization.Encoding.PEM))

    # store fake host
    with open("fake_host.crt", "wb") as f:
        f.write(fake_host_crt.public_bytes(serialization.Encoding.PEM))

    with open("host_crt_expired.crt", "wb") as f:
        f.write(host_crt_expired.public_bytes(serialization.Encoding.PEM))

    # store a DER cert and crl
    with open("der.crt", "wb") as f:
        f.write(ibm_pougkeepsie_crt.public_bytes(serialization.Encoding.DER))
    with open("der.crl", "wb") as f:
        f.write(ibm_poughkeepsie_crl.public_bytes(serialization.Encoding.DER))

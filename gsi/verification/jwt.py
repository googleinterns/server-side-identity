from collections.abc import Mapping
import datetime
import json

import cachetools
import six
from six.moves import urllib

from gsi.verification import _helpers
from gsi.verification import crypt

try:
    from gsi.verification.crypt import es256
except ImportError:  # pragma: NO COVER
    es256 = None

_ALGORITHM_TO_VERIFIER_CLASS = {"RS256": crypt.RSAVerifier}
_CRYPTOGRAPHY_BASED_ALGORITHMS = frozenset(["ES256"])

if es256 is not None:  # pragma: NO COVER
    _ALGORITHM_TO_VERIFIER_CLASS["ES256"] = es256.ES256Verifier


def encode(signer, payload, header=None, key_id=None):
    """Make a signed JWT.
    Args:
        signer (gsi.verification.crypt.Signer): The signer used to sign the JWT.
        payload (Mapping[str, str]): The JWT payload.
        header (Mapping[str, str]): Additional JWT header payload.
        key_id (str): The key id to add to the JWT header. If the
            signer has a key id it will be used as the default. If this is
            specified it will override the signer's key id.
    Returns:
        bytes: The encoded JWT.
    """
    if header is None:
        header = {}

    if key_id is None:
        key_id = signer.key_id

    header.update({"typ": "JWT"})

    if es256 is not None and isinstance(signer, es256.ES256Signer):
        header.update({"alg": "ES256"})
    else:
        header.update({"alg": "RS256"})

    if key_id is not None:
        header["kid"] = key_id

    segments = [
        _helpers.unpadded_urlsafe_b64encode(json.dumps(header).encode("utf-8")),
        _helpers.unpadded_urlsafe_b64encode(json.dumps(payload).encode("utf-8")),
    ]

    signing_input = b".".join(segments)
    signature = signer.sign(signing_input)
    segments.append(_helpers.unpadded_urlsafe_b64encode(signature))

    return b".".join(segments)


def _decode_jwt_segment(encoded_section):
    """Decodes a single JWT segment."""
    section_bytes = _helpers.padded_urlsafe_b64decode(encoded_section)
    try:
        return json.loads(section_bytes.decode("utf-8"))
    except ValueError as caught_exc:
        new_exc = ValueError("Can't parse segment: {0}".format(section_bytes))
        six.raise_from(new_exc, caught_exc)


def _unverified_decode(token):
    """Decodes a token and does no verification.
    Args:
        token (Union[str, bytes]): The encoded JWT.
    Returns:
        Tuple[str, str, str, str]: header, payload, signed_section, and
            signature.
    Raises:
        ValueError: if there are an incorrect amount of segments in the token.
    """
    token = _helpers.to_bytes(token)

    if token.count(b".") != 2:
        raise ValueError("Wrong number of segments in token: {0}".format(token))

    encoded_header, encoded_payload, signature = token.split(b".")
    signed_section = encoded_header + b"." + encoded_payload
    signature = _helpers.padded_urlsafe_b64decode(signature)

    # Parse segments
    header = _decode_jwt_segment(encoded_header)
    payload = _decode_jwt_segment(encoded_payload)

    return header, payload, signed_section, signature


def decode_header(token):
    """Return the decoded header of a token.
    No verification is done. This is useful to extract the key id from
    the header in order to acquire the appropriate certificate to verify
    the token.
    Args:
        token (Union[str, bytes]): the encoded JWT.
    Returns:
        Mapping: The decoded JWT header.
    """
    header, _, _, _ = _unverified_decode(token)
    return header


def _verify_iat_and_exp(payload):
    """Verifies the ``iat`` (Issued At) and ``exp`` (Expires) claims in a token
    payload.
    Args:
        payload (Mapping[str, str]): The JWT payload.
    Raises:
        ValueError: if any checks failed.
    """
    now = _helpers.datetime_to_secs(_helpers.utcnow())

    # Make sure the iat and exp claims are present.
    for key in ("iat", "exp"):
        if key not in payload:
            raise ValueError("Token does not contain required claim {}".format(key))

    # Make sure the token wasn't issued in the future.
    iat = payload["iat"]
    # Err on the side of accepting a token that is slightly early to account
    # for clock skew.
    earliest = iat - _helpers.CLOCK_SKEW_SECS
    if now < earliest:
        raise ValueError("Token used too early, {} < {}".format(now, iat))

    # Make sure the token wasn't issued in the past.
    exp = payload["exp"]
    # Err on the side of accepting a token that is slightly out of date
    # to account for clow skew.
    latest = exp + _helpers.CLOCK_SKEW_SECS
    if latest < now:
        raise ValueError("Token expired, {} < {}".format(latest, now))


def decode(token, certs=None, verify=True, audience=None):
    """Decode and verify a JWT.
    Args:
        token (str): The encoded JWT.
        certs (Union[str, bytes, Mapping[str, Union[str, bytes]]]): The
            certificate used to validate the JWT signature. If bytes or string,
            it must the the public key certificate in PEM format. If a mapping,
            it must be a mapping of key IDs to public key certificates in PEM
            format. The mapping must contain the same key ID that's specified
            in the token's header.
        verify (bool): Whether to perform signature and claim validation.
            Verification is done by default.
        audience (list[str]): A collection of possible audience claims, 'aud', one of which 
            this JWT should contain. If None then the JWT's 'aud' parameter is not verified.
    Returns:
        Mapping[str, str]: The deserialized JSON payload in the JWT.
    Raises:
        ValueError: if any verification checks failed.
    """
    header, payload, signed_section, signature = _unverified_decode(token)

    if not verify:
        return payload

    # Pluck the key id and algorithm from the header and make sure we have
    # a verifier that can support it.
    key_alg = header.get("alg")
    key_id = header.get("kid")

    try:
        verifier_cls = _ALGORITHM_TO_VERIFIER_CLASS[key_alg]
    except KeyError as exc:
        if key_alg in _CRYPTOGRAPHY_BASED_ALGORITHMS:
            six.raise_from(
                ValueError(
                    "The key algorithm {} requires the cryptography package "
                    "to be installed.".format(key_alg)
                ),
                exc,
            )
        else:
            six.raise_from(
                ValueError("Unsupported signature algorithm {}".format(key_alg)), exc
            )

    # If certs is specified as a dictionary of key IDs to certificates, then
    # use the certificate identified by the key ID in the token header.
    if isinstance(certs, Mapping):
        if key_id:
            if key_id not in certs:
                raise ValueError("Certificate for key id {} not found.".format(key_id))
            certs_to_check = [certs[key_id]]
        # If there's no key id in the header, check against all of the certs.
        else:
            certs_to_check = certs.values()
    else:
        certs_to_check = certs

    # Verify that the signature matches the message.
    if not crypt.verify_signature(
        signed_section, signature, certs_to_check, verifier_cls
    ):
        raise ValueError("Could not verify token signature.")

    # Verify the issued at and created times in the payload.
    _verify_iat_and_exp(payload)

    # Check audience.
    if audience is not None:
        claim_audience = payload.get("aud")
        if claim_audience not in audience:
            raise ValueError(
                "Token has wrong audience {}, expected one of {}".format(
                    claim_audience, audience
                )
            )

    return payload


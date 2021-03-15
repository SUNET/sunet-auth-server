# -*- coding: utf-8 -*-
import json
import logging
from os import environ, path
from typing import Optional

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_pem_x509_certificate
from fastapi import FastAPI, Header, HTTPException
from jwcrypto import jwk, jwt
from pydantic import parse_obj_as
from starlette.responses import Response

from auth_server.log import setup_logging
from auth_server.mdq import xml_mdq_get
from auth_server.models import AccessToken, AuthRequest, AuthResponse, Claims, Proof

__author__ = 'lundberg'

setup_logging()
logger = logging.getLogger(__name__)

HOST = environ.get('HOST', '0.0.0.0')
PORT = environ.get('PORT', 3000)
BASE_URL = environ.get('BASE_URL', '')
MDQ_SERVER = environ.get('MDQ_SERVER', 'no_mdq_server_set')
KEYSTORE_PATH = environ.get('KEYSTORE', 'keystore.jwks')
AUDIENCE = environ.get('AUDIENCE')
TEST_MODE = environ.get('TEST_MODE', False)  # This is dangerous and turns off security - only for debugging
EXPIRES_IN = environ.get('EXPIRES_IN', 'P10D')

if path.exists(KEYSTORE_PATH):
    with open(KEYSTORE_PATH, 'r') as f:
        jwks = jwk.JWKSet.from_json(f.read())
        logger.info(f'jwks loaded from {KEYSTORE_PATH}')
else:
    logger.info('Creating new jwks')
    key = jwk.JWK.generate(kid='default', kty='EC', crv='P-256')
    jwks = jwk.JWKSet()
    jwks.add(key)
    with open(KEYSTORE_PATH, 'w') as f:
        json.dump(jwks.export(as_dict=True), f)
        logger.info(f'jwks written to {KEYSTORE_PATH}')

# Hack to be backwards compatible with thiss-auth
# TODO: use jwks.get_key('default')
signing_key: jwk.JWK = next(iter(jwks['keys']))


app = FastAPI()


@app.get('/.well-known/jwks.json', response_model=jwk.JWKSet)
async def get_jwks():
    return jwks.export(private_keys=False, as_dict=True)


@app.get('/.well-known/jwk.json', response_model=jwk.JWK)
async def get_jwk():
    return signing_key.export(private_key=False, as_dict=True)


@app.get('/.well-known/public.pem', response_class=Response)
async def get_public_pem():
    data = signing_key.export_to_pem(private_key=False)
    return Response(content=data, media_type='application/x-pem-file')


@app.post('/transaction', response_model=AuthResponse)
async def transaction(auth_req: AuthRequest, ssl_client_cert: Optional[str] = Header(None)):
    proof_ok = False
    entity_id = auth_req.keys.kid
    origins = auth_req.resources.origins
    logger.debug(f'entity_id: {entity_id}')
    logger.debug(f'origins: {origins}')

    mdq_certs = await xml_mdq_get(entity_id=entity_id, mdq_url=MDQ_SERVER)
    if mdq_certs is None:
        raise HTTPException(status_code=400, detail=f'{entity_id} not found')

    if auth_req.keys.proof is Proof.MTLS:
        if ssl_client_cert is None:
            raise HTTPException(status_code=400, detail='no client certificate')
        # Load client cert
        raw_cert = f'-----BEGIN CERTIFICATE-----\n{ssl_client_cert}\n-----END CERTIFICATE-----'
        client_cert = load_pem_x509_certificate(raw_cert.encode())
        cc_fingerprint = client_cert.fingerprint(SHA256())
        logger.debug(f'client cert fingerprint: {str(cc_fingerprint)}')
        # Compare fingerprints
        for item in mdq_certs:
            mdq_fingerprint = item.cert.fingerprint(SHA256())
            logger.debug(f'metadata {item.use} cert fingerprint: {str(mdq_fingerprint)}')
            if mdq_fingerprint == cc_fingerprint:
                proof_ok = True
                logger.info(f'{entity_id} metadata {item.use} cert fingerprint matches client cert fingerprint')
                break
    elif auth_req.keys.proof is Proof.HTTPSIGN:
        raise HTTPException(status_code=400, detail='httpsign is not implemented')
    elif auth_req.keys.proof is Proof.TEST and parse_obj_as(bool, TEST_MODE) is True:
        logger.info(f'TEST_MODE: {TEST_MODE} - access token will be returned with no proof')
        proof_ok = True
    else:
        raise HTTPException(status_code=400, detail='no supported proof method')

    if proof_ok:
        # Create access token
        claims = Claims(origins=origins, exp=EXPIRES_IN, aud=AUDIENCE)
        token = jwt.JWT(header={'alg': 'HS256'}, claims=claims.to_rfc7519())
        token.make_signed_token(signing_key)
        auth_response = AuthResponse(access_token=AccessToken(type='bearer', value=token.serialize()))
        logger.info(f'OK:{entity_id}:{AUDIENCE}:{origins}')
        return auth_response

    return HTTPException(status_code=401, detail='permission denied')

# GNAP (RFC 9635) Implementation Review - SUNET Auth Server

## Overall Assessment

This is a **solid, production-ready GNAP implementation** for the eduID IAM suite with good adherence to RFC 9635. The flow-based architecture is well-designed and extensible.

## Compliance Summary

| Feature | Status | Notes |
|---------|--------|-------|
| Grant Request (`/transaction`) | ✅ Good | Full model support |
| Access Tokens | ✅ Good | JWT-based with claims |
| Key Proofing - mTLS | ✅ Implemented | `proof/mtls.py` |
| Key Proofing - JWS | ✅ Implemented | `proof/jws.py` |
| Key Proofing - JWSD | ✅ Implemented | `proof/jws.py` |
| Key Proofing - httpsig | ❌ Not implemented | Raises exception |
| Interaction - redirect | ✅ Implemented | |
| Interaction - user_code | ✅ Implemented | |
| Interaction - app | ❌ Not supported | Defined but not functional |
| Continuation API | ✅ Mostly done | Missing DELETE/PATCH |
| Error Codes | ✅ Complete | All RFC codes defined |

## Key Findings

### Strengths

1. Comprehensive GNAP models in `src/auth_server/models/gnap.py`
2. Well-structured step-based flow pipeline in `flows.py`
3. Good interaction hash calculation per RFC 9635 Section 4.2.3
4. Multiple authentication flows (CA, MDQ, TLS-FED, Config, Interaction)

### Areas for Improvement

1. **Error responses** (`gnap.py:281`) - Uses `HTTPException` instead of RFC 9635 `ErrorResponse`:
   ```python
   # TODO: Change FastApi HTTPException responses to ErrorResponse
   ```

2. **Missing Cache-Control header** (`root.py:84-85`):
   ```python
   # TODO: Cache-Control: no-store
   ```

3. **httpsig not implemented** (`flows.py:174`) - The recommended default proof method:
   ```python
   raise NextFlowException(status_code=400, detail="httpsig proof method not implemented")
   ```

4. **Token management endpoint** (`root.py:177`) - Not implemented:
   ```python
   # TODO: implement token management
   ```

5. **Continuation token rotation** (`root.py:140-143`) - Incomplete:
   ```python
   # TODO: the transaction reference shouldn't be returned again
   # TODO: the continuation access token should be rotated
   ```

6. **Client by reference** (`flows.py:278`) - Only key reference supported:
   ```python
   raise NextFlowException(status_code=400, detail="client by reference not implemented")
   ```

## Recommendations

### High Priority

- [ ] Implement `httpsig` (HTTP Message Signatures, RFC 9421) - it's the recommended default proof method in RFC 9635

### Medium Priority

- [ ] Return proper `ErrorResponse` objects instead of raw HTTPException for RFC compliance
- [ ] Add `Cache-Control: no-store` header to grant responses
- [ ] Create a userinfo/identity endpoint (typically protected by the access token)

### Low Priority

- [ ] Implement token management (rotation/revocation) endpoint
- [ ] Implement DELETE on `/continue` for grant revocation
- [ ] Implement `app` interaction start method

## Conclusion

The implementation is well-suited for its purpose as an authorization server for the eduID IAM suite, with good support for certificate-based authentication flows (CA, MDQ, TLS-FED) which are particularly relevant for federated identity scenarios.

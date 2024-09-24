# SAML 2.0 Server Configuration Guide

### SAML 2.0 SAML Response feature testing checklist

- [x] ⁠SAML case 1: Unsigned Assertion, <del>Unsigned</del> Signed Response, Without EncryptedAssertion
- [x] SAML case 2: Signed Assertion, Unsigned Response, Without EncryptedAssertion
- [x] ⁠SAML case 3: Unsigned Assertion, Signed Response, Without EncryptedAssertion
- [ ] ⁠SAML case 4: Unsigned Assertion, ~~Unsigned~~ Signed Response, With EncryptedAssertin
- [ ] ⁠SAML case 5: Signed Assertion, Signed Response, Without EncryptedAssertin
- [ ] ⁠SAML case 6: Signed Assertion, Unsigned Response, With EncryptedAssertin
- [ ] SAML case 7: Unsigned Assertion, Signed Response, With EncryptedAssertion
- [ ] ⁠SAML case 8: Signed Assertion, Signed Response, With EncryptedAssertion

Note: Either Assertion or Response or both will be always signed. Assertion can be encrypted or not encrypted.

## CASE 1. SIGNED SAML REQUEST

```javascript
// IN IDP
wantAuthnRequestsSigned = true; // default is false
// IN SP
authnRequestsSigned = true; // default is false
```

## CASE 2. SIGNED SAML RESPONSE (ASSERTION) + UNSIGNED MESSAGE + NO ENCRYPTION (ASSERTION)

```javascript
// IN SP
wantAssertionsSigned = true; // default is false
```

## CASE 3. SIGNED ASSERTION + ENCRYPTED ASSERTION + UNSIGNED MESSAGE

```javascript
// IN SP
wantAssertionsSigned = true; // default is false
// IN IDP
isAssertionEncrypted: true, // default is false
```

## CASE 4. UNSIGNED ASSERTION + NO ENCRYPTED ASSERTION + SIGNED MESSAGE

```javascript
// IN SP
wantMessageSigned: true, // default is false
```

## CASE 5. SIGNED ASSERTION + SIGNED MESSAGE + NO ENCRYPTED ASSERTION

```javascript
// IN SP
wantMessageSigned: true;
wantAssertionsSigned = true;
```

## CASE 6. SIGNED ASSERTION + SIGNED MESSAGE + ENCRYPTED ASSERTION

```javascript
// IN SP
wantMessageSigned: true;
wantAssertionsSigned = true;
// IN IDP
isAssertionEncrypted: true;
```

# Author

- [Nitesh Singh](https://www.linkedin.com/in/iamnitesh/)

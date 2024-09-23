# SAML 2.0 Server Configuration Guide

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

(define-constant ERR-NOT-AUTHORIZED (err u300))
(define-constant ERR-CREDENTIAL-EXISTS (err u301))
(define-constant ERR-CREDENTIAL-NOT-FOUND (err u302))
(define-constant ERR-ISSUER-NOT-APPROVED (err u303))
(define-constant ERR-CREDENTIAL-EXPIRED (err u304))
(define-constant ERR-INVALID-EXPIRY (err u305))

(define-map approved-issuers
  { issuer: principal }
  { 
    approved-at: uint,
    issuer-name: (string-ascii 64),
    is-active: bool 
  }
)

(define-map issued-credentials
  { recipient: principal, issuer: principal, credential-type: (string-ascii 32) }
  {
    credential-data: (string-utf8 256),
    issued-at: uint,
    expires-at: (optional uint),
    is-public: bool,
    verification-hash: (buff 32)
  }
)

(define-map credential-counts
  { recipient: principal }
  { count: uint }
)

(define-data-var contract-owner principal tx-sender)

(define-public (approve-issuer (issuer principal) (issuer-name (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
    (map-set approved-issuers
      { issuer: issuer }
      {
        approved-at: stacks-block-height,
        issuer-name: issuer-name,
        is-active: true
      }
    )
    (ok true)
  )
)

(define-public (issue-credential 
  (recipient principal) 
  (credential-type (string-ascii 32)) 
  (credential-data (string-utf8 256))
  (expires-at (optional uint))
  (verification-hash (buff 32)))
  (let ((issuer tx-sender))
    (asserts! (is-some (map-get? approved-issuers { issuer: issuer })) ERR-ISSUER-NOT-APPROVED)
    (asserts! (is-none (map-get? issued-credentials 
      { recipient: recipient, issuer: issuer, credential-type: credential-type })) 
      ERR-CREDENTIAL-EXISTS)
    (match expires-at
      expiry (asserts! (> expiry stacks-block-height) ERR-INVALID-EXPIRY)
      true
    )
    (map-set issued-credentials
      { recipient: recipient, issuer: issuer, credential-type: credential-type }
      {
        credential-data: credential-data,
        issued-at: stacks-block-height,
        expires-at: expires-at,
        is-public: false,
        verification-hash: verification-hash
      }
    )
    (let ((current-count (default-to u0 (get count (map-get? credential-counts { recipient: recipient })))))
      (map-set credential-counts
        { recipient: recipient }
        { count: (+ current-count u1) }
      )
    )
    (ok true)
  )
)

(define-public (set-credential-visibility 
  (issuer principal) 
  (credential-type (string-ascii 32)) 
  (is-public bool))
  (let ((recipient tx-sender))
    (match (map-get? issued-credentials 
      { recipient: recipient, issuer: issuer, credential-type: credential-type })
      credential
      (begin
        (map-set issued-credentials
          { recipient: recipient, issuer: issuer, credential-type: credential-type }
          (merge credential { is-public: is-public })
        )
        (ok true)
      )
      ERR-CREDENTIAL-NOT-FOUND
    )
  )
)

(define-read-only (get-credential (recipient principal) (issuer principal) (credential-type (string-ascii 32)))
  (match (map-get? issued-credentials 
    { recipient: recipient, issuer: issuer, credential-type: credential-type })
    credential
    (if (get is-public credential)
      (some credential)
      (if (is-eq tx-sender recipient)
        (some credential)
        none
      )
    )
    none
  )
)

(define-read-only (verify-credential 
  (recipient principal) 
  (issuer principal) 
  (credential-type (string-ascii 32))
  (verification-hash (buff 32)))
  (match (get-credential recipient issuer credential-type)
    credential
    (begin
      (match (get expires-at credential)
        expiry (and 
          (is-eq (get verification-hash credential) verification-hash)
          (> expiry stacks-block-height))
        (is-eq (get verification-hash credential) verification-hash)
      )
    )
    false
  )
)

(define-read-only (get-issuer-info (issuer principal))
  (map-get? approved-issuers { issuer: issuer })
)

(define-read-only (get-credential-count (recipient principal))
  (default-to u0 (get count (map-get? credential-counts { recipient: recipient })))
)

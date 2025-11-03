(define-constant ERR-NOT-AUTHORIZED (err u400))
(define-constant ERR-DELEGATION-EXISTS (err u401))
(define-constant ERR-DELEGATION-NOT-FOUND (err u402))
(define-constant ERR-DELEGATION-EXPIRED (err u403))
(define-constant ERR-INVALID-EXPIRY (err u404))
(define-constant ERR-SELF-DELEGATION (err u405))
(define-constant ERR-DELEGATION-REVOKED (err u406))

(define-map delegations
  { 
    delegator: principal,
    delegate: principal,
    credential-issuer: principal,
    credential-type: (string-ascii 32)
  }
  {
    granted-at: uint,
    expires-at: uint,
    purpose: (string-ascii 128),
    is-active: bool,
    usage-count: uint,
    max-uses: (optional uint)
  }
)

(define-map delegation-count
  { delegator: principal }
  { active-count: uint }
)

(define-public (delegate-credential
  (delegate principal)
  (credential-issuer principal)
  (credential-type (string-ascii 32))
  (expires-at uint)
  (purpose (string-ascii 128))
  (max-uses (optional uint)))
  (let ((delegator tx-sender))
    (asserts! (not (is-eq delegator delegate)) ERR-SELF-DELEGATION)
    (asserts! (> expires-at stacks-block-height) ERR-INVALID-EXPIRY)
    (asserts! (is-none (map-get? delegations
      { delegator: delegator, delegate: delegate, credential-issuer: credential-issuer, credential-type: credential-type }))
      ERR-DELEGATION-EXISTS)
    (map-set delegations
      { delegator: delegator, delegate: delegate, credential-issuer: credential-issuer, credential-type: credential-type }
      {
        granted-at: stacks-block-height,
        expires-at: expires-at,
        purpose: purpose,
        is-active: true,
        usage-count: u0,
        max-uses: max-uses
      }
    )
    (let ((current-count (default-to u0 (get active-count (map-get? delegation-count { delegator: delegator })))))
      (map-set delegation-count
        { delegator: delegator }
        { active-count: (+ current-count u1) }
      )
    )
    (ok true)
  )
)

(define-public (revoke-delegation
  (delegate principal)
  (credential-issuer principal)
  (credential-type (string-ascii 32)))
  (let ((delegator tx-sender))
    (match (map-get? delegations
      { delegator: delegator, delegate: delegate, credential-issuer: credential-issuer, credential-type: credential-type })
      delegation
      (if (get is-active delegation)
        (begin
          (map-set delegations
            { delegator: delegator, delegate: delegate, credential-issuer: credential-issuer, credential-type: credential-type }
            (merge delegation { is-active: false })
          )
          (let ((current-count (default-to u0 (get active-count (map-get? delegation-count { delegator: delegator })))))
            (map-set delegation-count
              { delegator: delegator }
              { active-count: (- current-count u1) }
            )
          )
          (ok true)
        )
        ERR-DELEGATION-REVOKED
      )
      ERR-DELEGATION-NOT-FOUND
    )
  )
)

(define-public (record-delegation-use
  (delegator principal)
  (credential-issuer principal)
  (credential-type (string-ascii 32)))
  (let ((delegate tx-sender))
    (match (map-get? delegations
      { delegator: delegator, delegate: delegate, credential-issuer: credential-issuer, credential-type: credential-type })
      delegation
      (begin
        (asserts! (get is-active delegation) ERR-DELEGATION-REVOKED)
        (asserts! (> (get expires-at delegation) stacks-block-height) ERR-DELEGATION-EXPIRED)
        (match (get max-uses delegation)
          max-use-limit
          (asserts! (< (get usage-count delegation) max-use-limit) ERR-NOT-AUTHORIZED)
          true
        )
        (map-set delegations
          { delegator: delegator, delegate: delegate, credential-issuer: credential-issuer, credential-type: credential-type }
          (merge delegation { usage-count: (+ (get usage-count delegation) u1) })
        )
        (ok true)
      )
      ERR-DELEGATION-NOT-FOUND
    )
  )
)

(define-read-only (get-delegation
  (delegator principal)
  (delegate principal)
  (credential-issuer principal)
  (credential-type (string-ascii 32)))
  (map-get? delegations
    { delegator: delegator, delegate: delegate, credential-issuer: credential-issuer, credential-type: credential-type })
)

(define-read-only (is-delegation-valid
  (delegator principal)
  (delegate principal)
  (credential-issuer principal)
  (credential-type (string-ascii 32)))
  (match (get-delegation delegator delegate credential-issuer credential-type)
    delegation
    (and
      (get is-active delegation)
      (> (get expires-at delegation) stacks-block-height)
      (match (get max-uses delegation)
        max-limit (< (get usage-count delegation) max-limit)
        true
      )
    )
    false
  )
)

(define-read-only (get-active-delegation-count (delegator principal))
  (default-to u0 (get active-count (map-get? delegation-count { delegator: delegator })))
)

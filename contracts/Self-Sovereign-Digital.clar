(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-IDENTITY-NOT-FOUND (err u101))
(define-constant ERR-ATTRIBUTE-NOT-FOUND (err u102))
(define-constant ERR-INVALID-SIGNATURE (err u103))
(define-constant ERR-PERMISSION-DENIED (err u104))
(define-constant ERR-IDENTITY-EXISTS (err u105))
(define-constant ERR-INVALID-EXPIRY (err u106))
(define-constant ERR-SELF-ENDORSEMENT (err u107))
(define-constant ERR-ENDORSEMENT-NOT-FOUND (err u108))
(define-constant ERR-ALREADY-ENDORSED (err u109))

(define-map identities
  { owner: principal }
  {
    created-at: uint,
    is-active: bool,
    recovery-key: (optional principal)
  }
)

(define-map identity-attributes
  { owner: principal, attribute-key: (string-ascii 64) }
  {
    value: (string-utf8 256),
    is-public: bool,
    created-at: uint,
    updated-at: uint
  }
)

(define-map access-permissions
  { owner: principal, requester: principal, attribute-key: (string-ascii 64) }
  {
    granted: bool,
    expires-at: uint,
    granted-at: uint
  }
)

(define-map verification-requests
  { request-id: uint }
  {
    requester: principal,
    owner: principal,
    attribute-key: (string-ascii 64),
    status: (string-ascii 20),
    created-at: uint,
    expires-at: uint
  }
)

(define-data-var next-request-id uint u1)

(define-public (create-identity (recovery-key (optional principal)))
  (let ((caller tx-sender))
    (asserts! (is-none (map-get? identities { owner: caller })) ERR-IDENTITY-EXISTS)
    (map-set identities
      { owner: caller }
      {
        created-at: stacks-block-height,
        is-active: true,
        recovery-key: recovery-key
      }
    )
    (ok true)
  )
)

(define-public (deactivate-identity)
  (let ((caller tx-sender))
    (match (map-get? identities { owner: caller })
      identity-data
      (begin
        (map-set identities
          { owner: caller }
          (merge identity-data { is-active: false })
        )
        (ok true)
      )
      ERR-IDENTITY-NOT-FOUND
    )
  )
)

(define-public (set-recovery-key (new-recovery-key principal))
  (let ((caller tx-sender))
    (match (map-get? identities { owner: caller })
      identity-data
      (begin
        (asserts! (get is-active identity-data) ERR-NOT-AUTHORIZED)
        (map-set identities
          { owner: caller }
          (merge identity-data { recovery-key: (some new-recovery-key) })
        )
        (ok true)
      )
      ERR-IDENTITY-NOT-FOUND
    )
  )
)

(define-public (add-attribute (attribute-key (string-ascii 64)) (value (string-utf8 256)) (is-public bool))
  (let ((caller tx-sender))
    (match (map-get? identities { owner: caller })
      identity-data
      (begin
        (asserts! (get is-active identity-data) ERR-NOT-AUTHORIZED)
        (map-set identity-attributes
          { owner: caller, attribute-key: attribute-key }
          {
            value: value,
            is-public: is-public,
            created-at: stacks-block-height,
            updated-at: stacks-block-height
          }
        )
        (ok true)
      )
      ERR-IDENTITY-NOT-FOUND
    )
  )
)

(define-public (update-attribute (attribute-key (string-ascii 64)) (value (string-utf8 256)) (is-public bool))
  (let ((caller tx-sender))
    (match (map-get? identity-attributes { owner: caller, attribute-key: attribute-key })
      attribute-data
      (begin
        (map-set identity-attributes
          { owner: caller, attribute-key: attribute-key }
          (merge attribute-data {
            value: value,
            is-public: is-public,
            updated-at: stacks-block-height
          })
        )
        (ok true)
      )
      ERR-ATTRIBUTE-NOT-FOUND
    )
  )
)

(define-public (remove-attribute (attribute-key (string-ascii 64)))
  (let ((caller tx-sender))
    (match (map-get? identity-attributes { owner: caller, attribute-key: attribute-key })
      attribute-data
      (begin
        (map-delete identity-attributes { owner: caller, attribute-key: attribute-key })
        (ok true)
      )
      ERR-ATTRIBUTE-NOT-FOUND
    )
  )
)

(define-public (grant-access (requester principal) (attribute-key (string-ascii 64)) (expires-at uint))
  (let ((caller tx-sender))
    (asserts! (> expires-at stacks-block-height) ERR-INVALID-EXPIRY)
    (match (map-get? identity-attributes { owner: caller, attribute-key: attribute-key })
      attribute-data
      (begin
        (map-set access-permissions
          { owner: caller, requester: requester, attribute-key: attribute-key }
          {
            granted: true,
            expires-at: expires-at,
            granted-at: stacks-block-height
          }
        )
        (ok true)
      )
      ERR-ATTRIBUTE-NOT-FOUND
    )
  )
)

(define-public (revoke-access (requester principal) (attribute-key (string-ascii 64)))
  (let ((caller tx-sender))
    (match (map-get? access-permissions { owner: caller, requester: requester, attribute-key: attribute-key })
      permission-data
      (begin
        (map-set access-permissions
          { owner: caller, requester: requester, attribute-key: attribute-key }
          (merge permission-data { granted: false })
        )
        (ok true)
      )
      ERR-PERMISSION-DENIED
    )
  )
)

(define-public (request-verification (owner principal) (attribute-key (string-ascii 64)) (expires-at uint))
  (let (
    (caller tx-sender)
    (request-id (var-get next-request-id))
  )
    (asserts! (> expires-at stacks-block-height) ERR-INVALID-EXPIRY)
    (map-set verification-requests
      { request-id: request-id }
      {
        requester: caller,
        owner: owner,
        attribute-key: attribute-key,
        status: "pending",
        created-at: stacks-block-height,
        expires-at: expires-at
      }
    )
    (var-set next-request-id (+ request-id u1))
    (ok request-id)
  )
)

(define-public (approve-verification-request (request-id uint))
  (let ((caller tx-sender))
    (match (map-get? verification-requests { request-id: request-id })
      request-data
      (begin
        (asserts! (is-eq caller (get owner request-data)) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status request-data) "pending") ERR-NOT-AUTHORIZED)
        (asserts! (> (get expires-at request-data) stacks-block-height) ERR-INVALID-EXPIRY)
        (map-set verification-requests
          { request-id: request-id }
          (merge request-data { status: "approved" })
        )
        (ok true)
      )
      ERR-PERMISSION-DENIED
    )
  )
)

(define-public (reject-verification-request (request-id uint))
  (let ((caller tx-sender))
    (match (map-get? verification-requests { request-id: request-id })
      request-data
      (begin
        (asserts! (is-eq caller (get owner request-data)) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status request-data) "pending") ERR-NOT-AUTHORIZED)
        (map-set verification-requests
          { request-id: request-id }
          (merge request-data { status: "rejected" })
        )
        (ok true)
      )
      ERR-PERMISSION-DENIED
    )
  )
)

(define-read-only (get-identity (owner principal))
  (map-get? identities { owner: owner })
)

(define-read-only (get-attribute (owner principal) (attribute-key (string-ascii 64)))
  (let ((caller tx-sender))
    (match (map-get? identity-attributes { owner: owner, attribute-key: attribute-key })
      attribute-data
      (if (get is-public attribute-data)
        (some attribute-data)
        (if (is-eq caller owner)
          (some attribute-data)
          (match (map-get? access-permissions { owner: owner, requester: caller, attribute-key: attribute-key })
            permission-data
            (if (and (get granted permission-data) (> (get expires-at permission-data) stacks-block-height))
              (some attribute-data)
              none
            )
            none
          )
        )
      )
      none
    )
  )
)

(define-read-only (get-access-permission (owner principal) (requester principal) (attribute-key (string-ascii 64)))
  (map-get? access-permissions { owner: owner, requester: requester, attribute-key: attribute-key })
)

(define-read-only (get-verification-request (request-id uint))
  (map-get? verification-requests { request-id: request-id })
)

(define-read-only (has-access (owner principal) (attribute-key (string-ascii 64)))
  (let ((caller tx-sender))
    (if (is-eq caller owner)
      true
      (match (map-get? access-permissions { owner: owner, requester: caller, attribute-key: attribute-key })
        permission-data
        (and (get granted permission-data) (> (get expires-at permission-data) stacks-block-height))
        false
      )
    )
  )
)


(define-map endorsements
  { endorser: principal, endorsee: principal }
  {
    weight: uint,
    reason: (string-ascii 128),
    created-at: uint,
    is-active: bool
  }
)

(define-map reputation-scores
  { identity: principal }
  {
    total-score: uint,
    endorsement-count: uint,
    last-updated: uint
  }
)

(define-public (endorse-identity (endorsee principal) (weight uint) (reason (string-ascii 128)))
  (let ((endorser tx-sender))
    (asserts! (not (is-eq endorser endorsee)) ERR-SELF-ENDORSEMENT)
    (asserts! (and (>= weight u1) (<= weight u10)) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? endorsements { endorser: endorser, endorsee: endorsee })) ERR-ALREADY-ENDORSED)
    (map-set endorsements
      { endorser: endorser, endorsee: endorsee }
      {
        weight: weight,
        reason: reason,
        created-at: stacks-block-height,
        is-active: true
      }
    )
    (update-reputation-score endorsee)
    (ok true)
  )
)

(define-public (revoke-endorsement (endorsee principal))
  (let ((endorser tx-sender))
    (match (map-get? endorsements { endorser: endorser, endorsee: endorsee })
      endorsement-data
      (begin
        (asserts! (get is-active endorsement-data) ERR-ENDORSEMENT-NOT-FOUND)
        (map-set endorsements
          { endorser: endorser, endorsee: endorsee }
          (merge endorsement-data { is-active: false })
        )
        (update-reputation-score endorsee)
        (ok true)
      )
      ERR-ENDORSEMENT-NOT-FOUND
    )
  )
)

(define-private (update-reputation-score (identity principal))
  (let (
    (score-data (calculate-reputation-score identity))
  )
    (map-set reputation-scores
      { identity: identity }
      {
        total-score: (get total-score score-data),
        endorsement-count: (get endorsement-count score-data),
        last-updated: stacks-block-height
      }
    )
  )
)

(define-private (calculate-reputation-score (identity principal))
  (let (
    (current-score (default-to { total-score: u0, endorsement-count: u0, last-updated: u0 }
                   (map-get? reputation-scores { identity: identity })))
  )
    { total-score: u0, endorsement-count: u0 }
  )
)

(define-read-only (get-reputation-score (identity principal))
  (map-get? reputation-scores { identity: identity })
)

(define-read-only (get-endorsement (endorser principal) (endorsee principal))
  (map-get? endorsements { endorser: endorser, endorsee: endorsee })
)

(define-read-only (has-endorsed (endorser principal) (endorsee principal))
  (match (map-get? endorsements { endorser: endorser, endorsee: endorsee })
    endorsement-data
    (get is-active endorsement-data)
    false
  )
)
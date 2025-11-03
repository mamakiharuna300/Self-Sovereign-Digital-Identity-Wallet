(define-constant ERR-NOT-AUTHORIZED (err u500))
(define-constant ERR-ATTESTATION-EXISTS (err u501))
(define-constant ERR-ATTESTATION-NOT-FOUND (err u502))
(define-constant ERR-INVALID-ATTESTATION (err u503))
(define-constant ERR-SELF-ATTESTATION (err u504))
(define-constant ERR-MAX-ATTESTATIONS-REACHED (err u505))

(define-map attestations
  { 
    credential-holder: principal,
    credential-issuer: principal,
    credential-type: (string-ascii 32),
    attester: principal
  }
  {
    attestation-hash: (buff 32),
    attested-at: uint,
    confidence-level: uint,
    notes: (string-ascii 128),
    is-active: bool
  }
)

(define-map attestation-counts
  { 
    credential-holder: principal,
    credential-issuer: principal,
    credential-type: (string-ascii 32)
  }
  { count: uint }
)

(define-map attester-stats
  { attester: principal }
  { total-attestations: uint, active-attestations: uint }
)

(define-data-var max-attestations-per-credential uint u50)

(define-public (attest-credential
  (credential-holder principal)
  (credential-issuer principal)
  (credential-type (string-ascii 32))
  (attestation-hash (buff 32))
  (confidence-level uint)
  (notes (string-ascii 128)))
  (let ((attester tx-sender))
    (asserts! (not (is-eq attester credential-holder)) ERR-SELF-ATTESTATION)
    (asserts! (and (>= confidence-level u1) (<= confidence-level u100)) ERR-INVALID-ATTESTATION)
    (asserts! (is-none (map-get? attestations 
      { credential-holder: credential-holder, credential-issuer: credential-issuer, 
        credential-type: credential-type, attester: attester })) 
      ERR-ATTESTATION-EXISTS)
    (let ((current-count (get-attestation-count credential-holder credential-issuer credential-type)))
      (asserts! (< current-count (var-get max-attestations-per-credential)) ERR-MAX-ATTESTATIONS-REACHED)
      (map-set attestations
        { credential-holder: credential-holder, credential-issuer: credential-issuer, 
          credential-type: credential-type, attester: attester }
        {
          attestation-hash: attestation-hash,
          attested-at: stacks-block-height,
          confidence-level: confidence-level,
          notes: notes,
          is-active: true
        }
      )
      (map-set attestation-counts
        { credential-holder: credential-holder, credential-issuer: credential-issuer, 
          credential-type: credential-type }
        { count: (+ current-count u1) }
      )
      (update-attester-stats attester true)
      (ok true)
    )
  )
)

(define-public (revoke-attestation
  (credential-holder principal)
  (credential-issuer principal)
  (credential-type (string-ascii 32)))
  (let ((attester tx-sender))
    (match (map-get? attestations 
      { credential-holder: credential-holder, credential-issuer: credential-issuer, 
        credential-type: credential-type, attester: attester })
      attestation
      (if (get is-active attestation)
        (begin
          (map-set attestations
            { credential-holder: credential-holder, credential-issuer: credential-issuer, 
              credential-type: credential-type, attester: attester }
            (merge attestation { is-active: false })
          )
          (update-attester-stats attester false)
          (ok true)
        )
        ERR-ATTESTATION-NOT-FOUND
      )
      ERR-ATTESTATION-NOT-FOUND
    )
  )
)

(define-private (update-attester-stats (attester principal) (is-new bool))
  (let ((stats (default-to { total-attestations: u0, active-attestations: u0 } 
                           (map-get? attester-stats { attester: attester }))))
    (map-set attester-stats
      { attester: attester }
      {
        total-attestations: (if is-new (+ (get total-attestations stats) u1) (get total-attestations stats)),
        active-attestations: (if is-new 
                              (+ (get active-attestations stats) u1)
                              (- (get active-attestations stats) u1))
      }
    )
  )
)

(define-read-only (get-attestation
  (credential-holder principal)
  (credential-issuer principal)
  (credential-type (string-ascii 32))
  (attester principal))
  (map-get? attestations 
    { credential-holder: credential-holder, credential-issuer: credential-issuer, 
      credential-type: credential-type, attester: attester })
)

(define-read-only (get-attestation-count
  (credential-holder principal)
  (credential-issuer principal)
  (credential-type (string-ascii 32)))
  (default-to u0 (get count (map-get? attestation-counts 
    { credential-holder: credential-holder, credential-issuer: credential-issuer, 
      credential-type: credential-type })))
)

(define-read-only (get-attester-stats (attester principal))
  (map-get? attester-stats { attester: attester })
)

(define-read-only (verify-attestation
  (credential-holder principal)
  (credential-issuer principal)
  (credential-type (string-ascii 32))
  (attester principal)
  (attestation-hash (buff 32)))
  (match (get-attestation credential-holder credential-issuer credential-type attester)
    attestation
    (and 
      (get is-active attestation)
      (is-eq (get attestation-hash attestation) attestation-hash))
    false
  )
)

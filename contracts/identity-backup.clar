(define-constant ERR-BACKUP-NOT-FOUND (err u200))
(define-constant ERR-RECOVERY-IN-PROGRESS (err u201))
(define-constant ERR-MAX-BACKUPS-REACHED (err u202))
(define-constant ERR-BACKUP-TOO-OLD (err u203))

(define-map identity-backups
  { owner: principal, backup-id: uint }
  {
    data-hash: (buff 32),
    encryption-key-hash: (buff 32),
    created-at: uint,
    expires-at: uint,
    attribute-count: uint
  }
)

(define-map backup-counters
  { owner: principal }
  { count: uint, next-id: uint }
)

(define-map recovery-sessions
  { owner: principal }
  {
    backup-id: uint,
    initiated-at: uint,
    expires-at: uint,
    status: (string-ascii 20)
  }
)

(define-data-var max-backups-per-identity uint u5)
(define-data-var backup-expiry-blocks uint u52560)

(define-public (create-backup (data-hash (buff 32)) (encryption-key-hash (buff 32)) (attribute-count uint))
  (let (
    (caller tx-sender)
    (counter-data (default-to { count: u0, next-id: u1 } (map-get? backup-counters { owner: caller })))
    (backup-id (get next-id counter-data))
    (current-count (get count counter-data))
  )
    (asserts! (< current-count (var-get max-backups-per-identity)) ERR-MAX-BACKUPS-REACHED)
    (map-set identity-backups
      { owner: caller, backup-id: backup-id }
      {
        data-hash: data-hash,
        encryption-key-hash: encryption-key-hash,
        created-at: stacks-block-height,
        expires-at: (+ stacks-block-height (var-get backup-expiry-blocks)),
        attribute-count: attribute-count
      }
    )
    (map-set backup-counters
      { owner: caller }
      { count: (+ current-count u1), next-id: (+ backup-id u1) }
    )
    (ok backup-id)
  )
)

(define-public (initiate-recovery (backup-id uint))
  (let ((caller tx-sender))
    (asserts! (is-none (map-get? recovery-sessions { owner: caller })) ERR-RECOVERY-IN-PROGRESS)
    (match (map-get? identity-backups { owner: caller, backup-id: backup-id })
      backup-data
      (begin
        (asserts! (> (get expires-at backup-data) stacks-block-height) ERR-BACKUP-TOO-OLD)
        (map-set recovery-sessions
          { owner: caller }
          {
            backup-id: backup-id,
            initiated-at: stacks-block-height,
            expires-at: (+ stacks-block-height u144),
            status: "initiated"
          }
        )
        (ok true)
      )
      ERR-BACKUP-NOT-FOUND
    )
  )
)

(define-public (delete-backup (backup-id uint))
  (let ((caller tx-sender))
    (match (map-get? identity-backups { owner: caller, backup-id: backup-id })
      backup-data
      (begin
        (map-delete identity-backups { owner: caller, backup-id: backup-id })
        (let ((counter-data (default-to { count: u0, next-id: u1 } (map-get? backup-counters { owner: caller }))))
          (map-set backup-counters
            { owner: caller }
            (merge counter-data { count: (- (get count counter-data) u1) })
          )
        )
        (ok true)
      )
      ERR-BACKUP-NOT-FOUND
    )
  )
)

(define-read-only (get-backup (owner principal) (backup-id uint))
  (map-get? identity-backups { owner: owner, backup-id: backup-id })
)

(define-read-only (get-backup-count (owner principal))
  (get count (default-to { count: u0, next-id: u1 } (map-get? backup-counters { owner: owner })))
)

(define-read-only (get-recovery-session (owner principal))
  (map-get? recovery-sessions { owner: owner })
)

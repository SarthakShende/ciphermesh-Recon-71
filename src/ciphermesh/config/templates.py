"""Generated example configuration.

Kept as a template rather than a checked-in file so that the comments can
refer to the actual validation rules in :mod:`ciphermesh.config.schema`,
and so there is exactly one source of truth for what a valid config looks
like.
"""

from __future__ import annotations

EXAMPLE_CONFIG = '''\
# =============================================================================
# CipherMesh Edge - node configuration
# =============================================================================
#
#   Location : /etc/ciphermesh/config.yaml      (0640 root:ciphermesh)
#   Secrets  : /etc/ciphermesh/ciphermesh.env   (0640 root:ciphermesh)
#
# NEVER write a secret in this file. Reference it from the environment:
#
#   ${CIPHERMESH_LORA_PASSPHRASE}
#   ${CIPHERMESH_API_TOKEN}
#   ${CIPHERMESH_CLOUD_API_KEY}
#   ${CIPHERMESH_CLOUD_DEVICE_TOKEN}
#
# ${VAR} is an error if VAR is unset. ${VAR:-fallback} is not.
#
# Unknown keys are rejected at startup. A typo is a failure, not a silent
# no-op.
#
# Validate this file at any time with:
#   ciphermesh config validate
# =============================================================================

device:
  # Unique per node. Carried in every event. Not a secret.
  id: CM-PI-001
  name: CipherMesh Gateway
  # GATEWAY_SENSOR = PI-A, reads the sensor and originates events.
  # RECEIVER_NODE = PI-B, receives, verifies and stores events.
  role: GATEWAY_SENSOR
  # location: "Lab, building A"
  # contact: ops@example.invalid

# -----------------------------------------------------------------------------
# Temperature / humidity sensor
# -----------------------------------------------------------------------------
sensor:
  enabled: true

  # Registry key. One of:
  #   mock    simulated, reports MOCK status, never claims to be hardware
  #   dht22   DHT22 / AM2302 / RHT03 single-wire sensor on one GPIO
  type: dht22

  # DHT22 wiring: VCC -> 3V3 (pin 1), GND -> GND (pin 6), DATA -> GPIO,
  # with a 4.7k-10k pull-up to 3V3 on DATA.
  # BCM numbering. Default 4 = physical pin 7.
  interface: "gpio:4"
  gpio_pin: 4
  gpio_chip: gpiochip0

  # Minimum 2s for DHT22: the AM2302 datasheet specifies a 2 second sampling
  # period and converting faster produces checksum failures. 5s is a good
  # default for a 5-second telemetry feed.
  interval_seconds: 5.0

  humidity_enabled: true

  # Reject readings outside the AM2302 operating range (-40..80 C, 0..100 %RH)
  # rather than propagating a corrupt frame.
  enforce_range: true

  # Retries within a single read before declaring the sensor disconnected.
  read_retries: 2
  frame_timeout_ms: 8.0
  failure_threshold: 3

  # --- mock only ---
  # mock_fixed_value: 26.0
  # mock_sweep: false

# -----------------------------------------------------------------------------
# Reticulum Network Stack
# -----------------------------------------------------------------------------
reticulum:
  enabled: true

  # Where the rendered Reticulum config lives. Empty => /etc/ciphermesh/reticulum
  # config_dir: ""

  # How PI-A addresses PI-B:
  #
  #   plain   A PLAIN destination. Both nodes derive the same addressable
  #           hash from the name, so packets are broadcast on every online
  #           interface. No announces, no transport node, no pairing. Link
  #           confidentiality comes from lora.passphrase (IFAC) instead.
  #           CipherMesh's own Ed25519 chain is the sole authenticity check.
  #
  #   group   GROUP destination, shared passphrase. Note the address hash
  #           still folds in the local identity, so a GROUP destination is
  #           NOT interchangeable with plain.
  #
  #   single  Per-node identities. PI-B announces, PI-A recalls by
  #           peer_destination_hash. Reticulum-native encryption and forward
  #           secrecy, at the cost of a pairing step.
  mode: plain

  app_name: ciphermesh
  aspects: ["event"]
  destination_name: ciphermesh.event

  loglevel: 4

  # Off for a 2-node deployment: with mode: plain the node does not need to
  # route for others, and staying off means it is not relaying traffic for
  # other mesh operators on shared IN865 spectrum.
  enable_transport: false

  # Off so this private instance does not contend with a personal Reticulum
  # instance running on the same host.
  share_instance: false

  # 0 disables announcing. Required for mode: single.
  announce_interval: 0

  # Required for mode: group. Must come from the environment.
  # group_passphrase: "${CIPHERMESH_RNS_GROUP_PASSPHRASE}"

  # Required for mode: single (32 hex chars). Set with:
  #   ciphermesh reticulum pair <hex-hash>
  peer_destination_hash: ""

  # Reticulum's MTU is 500, giving an MDU of 466 bytes.
  max_payload_bytes: 466

  # Return the verification verdict to the sender as a signed ACK.
  send_acknowledgements: true
  send_timeout: 8.0

# -----------------------------------------------------------------------------
# LoRa radio
# -----------------------------------------------------------------------------
lora:
  enabled: false

  # Reticulum speaks LoRa only through RNodeInterface, which requires a
  # board running RNode firmware (Heltec V3/V4, LilyGO T-Beam, RAK4631,
  # T-Beam + SX1262). A raw SPI module or an AT-command modem is NOT
  # supported and will be reported as UNSUPPORTED, not faked.
  interface: rnode

  # Absolute path to the RNode's serial port. Prefer the stable udev
  # symlink installed by install.sh, or a /dev/serial/by-id path.
  # device: /dev/ciphermesh/lora

  # RNodeInterface hardcodes 115200 baud. Shown for awareness only; any
  # other value is rejected.
  baud_rate: 115200

  # --- RF parameters, all required when enabled, none defaulted ---
  # frequency: 865062500
  # bandwidth: 125000
  # spreading_factor: 8
  # coding_rate: 5
  # tx_power: 10

  # Regulatory plan used to validate the above. Every value in
  # ciphermesh/config/regions.py carries a citation.
  # region: IN865-867

  # Transmit power ceiling you have confirmed applies to you. CipherMesh
  # does not choose this: the gazetted limit depends on the device category
  # (the 2021 Indian SRD rules list, for example, 25 mW ERP at 1% duty for
  # EN 300 220 non-specific SRD, and a separate 500 mW ERP category).
  # max_tx_power_dbm: 10

  # Must be true before the radio may transmit. Set by install.sh only after
  # you have confirmed the applicable limits.
  regulatory_confirmed: false
  # regulatory_reference: "Gazette of India 2021 SRD rules; 25 mW ERP; 1% duty"

  # Interface Access Control. Encrypts and authenticates every frame at the
  # link layer. BOTH Pis MUST use the same values or frames are dropped on
  # receive and events never arrive.
  # network_name: ciphermesh
  # passphrase: "${CIPHERMESH_LORA_PASSPHRASE}"

  # Optional RNode metadata
  id_interval: 0
  id_callsign: ""
  flow_control: false

  # Self-imposed cap on event payload size. A signed temperature event
  # encodes to roughly 142 bytes.
  max_payload_bytes: 200

# -----------------------------------------------------------------------------
# Cloud backend (Render / FastAPI)
# -----------------------------------------------------------------------------
cloud:
  # Off until the backend exists. When off, every CloudClient call returns
  # an explicit error; nothing is ever faked.
  enabled: false

  # api_url: https://api.ciphermesh.example
  # api_key: "${CIPHERMESH_CLOUD_API_KEY}"
  # device_token: "${CIPHERMESH_CLOUD_DEVICE_TOKEN}"

  request_timeout_seconds: 10.0
  connect_timeout_seconds: 5.0

  # Used only to answer "is there an internet connection at all". Kept
  # separate from api_url so a cloud outage is not reported as an internet
  # outage.
  connectivity_probe_url: https://connectivitycheck.gstatic.com/generate_204
  connectivity_probe_timeout: 5.0
  connectivity_cache_seconds: 30.0

  batch_size: 50

  # Present so the intent is explicit. There is no supported way to set this
  # to false.
  verify_tls: true

# -----------------------------------------------------------------------------
# Local storage
# -----------------------------------------------------------------------------
storage:
  # Empty => /var/lib/ciphermesh/ciphermesh.db
  sqlite_path: ""
  busy_timeout_ms: 5000
  journal_mode: WAL
  synchronous: NORMAL
  maintenance_interval_hours: 24
  # 0 disables pruning.
  event_retention_days: 0
  security_event_retention_days: 0

# -----------------------------------------------------------------------------
# Verification and replay policy
# -----------------------------------------------------------------------------
security:
  # An event older than this is rejected as STALE_EVENT.
  max_event_age_seconds: 900

  # Absorbs modest clock skew without opening a large future-timestamp gap.
  max_future_skew_seconds: 120

  # Primary replay defence. On by default.
  enforce_monotonic_sequence: true

  # Off by default. On a lossy LoRa link reordering is normal, and allowing
  # it weakens the sequence guarantee.
  allow_out_of_order: false
  out_of_order_tolerance: 0

  # How long event hashes are retained for duplicate detection.
  replay_window_seconds: 86400
  replay_window_max_entries: 100000

  # Off by default: an unknown device cannot be authenticated.
  auto_register_devices: false

  check_revocation: true
  record_security_events: true

  min_valid_unix_timestamp: 946684800    # 2000-01-01T00:00:00Z
  max_valid_unix_timestamp: 4102444800   # 2100-01-01T00:00:00Z

# -----------------------------------------------------------------------------
# Offline-first sync queue
# -----------------------------------------------------------------------------
sync:
  enabled: true
  interval_seconds: 30.0
  batch_size: 25

  # delay = min(base * 2^(attempt-1), max), then +/- jitter
  base_backoff_seconds: 15.0
  max_backoff_seconds: 3600.0
  jitter_fraction: 0.2

  # After this many failures a record moves to FAILED and waits for an
  # operator. Prevents an infinite retry loop against a dead backend.
  max_attempts: 12

  sync_on_reconnect: true
  retry_failed: false
  auto_register: true

# -----------------------------------------------------------------------------
# Local monitoring API
# -----------------------------------------------------------------------------
monitoring:
  enabled: true

  # 127.0.0.1 by default. For laptop access from PI-B, either forward the
  # port over SSH (recommended, stays loopback-only):
  #     ssh -L 8080:127.0.0.1:8080 pi@<pi-b-ip>
  # or bind to 0.0.0.0 with a token, in which case auth_token becomes
  # mandatory and the loader refuses to start without it.
  bind_address: 127.0.0.1
  port: 8080

  # auth_token: "${CIPHERMESH_API_TOKEN}"
  auth_required: false

  dashboard_enabled: true
  max_workers: 4
  default_event_limit: 50
  max_event_limit: 1000
  request_log_enabled: true

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging:
  level: INFO
  # json for machine consumption, text for reading during setup.
  format: json

  # Off by default: systemd already captures stdout to the journal.
  file_enabled: false
  file_name: ciphermesh.log
  max_file_bytes: 10485760
  backup_count: 3

  reticulum_log_enabled: true
  redact_keys:
    - api_key
    - device_token
    - auth_token
    - passphrase
    - group_passphrase
    - private_key
    - password
    - secret
    - authorization

# -----------------------------------------------------------------------------
# Event construction
# -----------------------------------------------------------------------------
event:
  version: 1

  # Placeholders: {date} {device} {sequence} {random}
  # The random component is what stops uniqueness depending on the clock
  # and sequence alone.
  id_template: "EVT-{date}-{device}-{sequence:08d}-{random}"
  random_suffix_bytes: 2

  # Applied when the reading is captured, so the signed value is the value
  # that gets displayed.
  value_decimals: 2
  default_unit: C
  default_event_type: TEMPERATURE
  max_canonical_bytes: 4096

# -----------------------------------------------------------------------------
# Software identity
# -----------------------------------------------------------------------------
application:
  software_version: 1.0.0
  # Empty => SHA-256 of the installed package tree, computed at runtime.
  application_hash: ""
  node_description: CipherMesh Edge
'''


def render_example_config() -> str:
    return EXAMPLE_CONFIG

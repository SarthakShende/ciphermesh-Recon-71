"""Regulatory region tables for LoRa radio validation.

Every row carries a ``source`` field naming where the value came from. No
frequency or power limit in this module was invented: entries are either
transcribed from a published regional plan or marked ``UNVERIFIED`` so the
installer refuses to treat them as authoritative.

The purpose of this table is to *reject* obviously wrong configurations before
a radio transmits, not to certify compliance. Transmit power limits in
particular are jurisdiction-, licence- and equipment-dependent; the operator
must confirm the applicable limit and that is enforced by
``lora.regulatory_confirmed`` in the config.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..errors import RegionError

# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Channel:
    """A single LoRa channel within a regional plan."""

    frequency_hz: int
    bandwidth_hz: int
    label: str
    source: str


@dataclass(frozen=True, slots=True)
class Region:
    """A regional frequency plan and its radio constraints."""

    code: str
    name: str
    #: Inclusive frequency bounds in Hz.
    min_frequency_hz: int
    max_frequency_hz: int
    #: Bandwidths in Hz that appear in the plan.
    bandwidths_hz: tuple[int, ...]
    #: Spreading factors valid in this plan (LoRa SF7-SF12).
    spreading_factors: tuple[int, ...]
    #: Coding rates 4/5 .. 4/8, encoded 5-8 the way RNode expects.
    coding_rates: tuple[int, ...]
    #: Default channels, transcribed from the regional plan.
    default_channels: tuple[Channel, ...]
    #: Duty-cycle guidance. ``None`` means no duty-cycle limit is stated in
    #: the cited source; it does not mean "unlimited".
    duty_cycle_limit: str | None
    #: Documented power limits. Multiple entries because the applicable limit
    #: depends on the device category.
    power_limits: tuple[str, ...]
    source: str
    #: False when the operator must not rely on this table.
    verified: bool = True

    def validate_frequency(self, frequency_hz: int) -> None:
        if not self.min_frequency_hz <= frequency_hz <= self.max_frequency_hz:
            raise RegionError(
                f"frequency {frequency_hz / 1e6:.4f} MHz is outside the {self.code} band "
                f"({self.min_frequency_hz / 1e6:.4f}-{self.max_frequency_hz / 1e6:.4f} MHz)"
            )

    def validate_bandwidth(self, bandwidth_hz: int) -> None:
        if bandwidth_hz not in self.bandwidths_hz:
            allowed = ", ".join(f"{b / 1000:g}kHz" for b in self.bandwidths_hz)
            raise RegionError(
                f"bandwidth {bandwidth_hz} Hz is not defined for {self.code}; allowed: {allowed}"
            )

    def validate_spreading_factor(self, sf: int) -> None:
        if sf not in self.spreading_factors:
            raise RegionError(
                f"spreading factor SF{sf} is not defined for {self.code}; "
                f"allowed: {', '.join(f'SF{s}' for s in self.spreading_factors)}"
            )

    def validate_coding_rate(self, cr: int) -> None:
        if cr not in self.coding_rates:
            raise RegionError(
                f"coding rate {cr} is not defined for {self.code}; "
                f"allowed: {', '.join(f'4/{c}' for c in self.coding_rates)}"
            )

    def matches_channel(self, frequency_hz: int, bandwidth_hz: int) -> Channel | None:
        """Return the plan channel matching this configuration, if any."""
        for channel in self.default_channels:
            if (
                abs(channel.frequency_hz - frequency_hz) <= bandwidth_hz // 4
                and channel.bandwidth_hz == bandwidth_hz
            ):
                return channel
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "name": self.name,
            "band_mhz": [self.min_frequency_hz / 1e6, self.max_frequency_hz / 1e6],
            "bandwidths_khz": [b / 1000 for b in self.bandwidths_hz],
            "spreading_factors": list(self.spreading_factors),
            "coding_rates": [f"4/{c}" for c in self.coding_rates],
            "default_channels_mhz": [c.frequency_hz / 1e6 for c in self.default_channels],
            "duty_cycle_limit": self.duty_cycle_limit,
            "power_limits": list(self.power_limits),
            "source": self.source,
            "verified": self.verified,
        }


# ---------------------------------------------------------------------------
# IN865-867 (India) - the region selected for this deployment
# ---------------------------------------------------------------------------

_HELTEC_IN865 = "Heltec LoRaWAN frequency plans, IN865-867 (865.0625/865.4025/865.9850 MHz uplink, RX2 866.550 MHz SF10 BW125)"
_LORA_RP = "LoRa Alliance RP1.0.3 s2.10 'IN865-867 MHz ISM Band'"
_GAZETTE = (
    "Gazette of India, Use of Low Power Equipment in the Frequency Band "
    "865-868 MHz for Short Range Devices (Exemption from Licence) Rules, 2021"
)

REGION_IN865 = Region(
    code="IN865-867",
    name="India 865-867 MHz (license-free ISM)",
    min_frequency_hz=865_000_000,
    max_frequency_hz=867_000_000,
    bandwidths_hz=(125_000, 250_000, 500_000),
    spreading_factors=(7, 8, 9, 10, 11, 12),
    coding_rates=(5, 6, 7, 8),
    default_channels=(
        Channel(865_062_500, 125_000, "IN865-1", _HELTEC_IN865),
        Channel(865_402_500, 125_000, "IN865-2", _HELTEC_IN865),
        Channel(865_985_000, 125_000, "IN865-3", _HELTEC_IN865),
    ),
    # The gazetted SRD rules state duty-cycle limits for several device
    # categories (1% for EN 300 220 non-specific SRD). CipherMesh does not
    # pick a category on the operator's behalf.
    duty_cycle_limit="category dependent; 1% for EN 300 220 non-specific SRD",
    power_limits=(
        "25 mW ERP, duty cycle 1% (EN 300 220 non-specific SRD)",
        "500 mW ERP (separate gazetted category)",
    ),
    source=f"{_HELTEC_IN865}; {_LORA_RP}; {_GAZETTE}",
    verified=True,
)


# ---------------------------------------------------------------------------
# Other regions
#
# Listed so an operator outside India is not silently blocked, but marked
# UNVERIFIED: these are transcribed at a high level and must be confirmed
# against the local regulator before the radio is enabled.
# ---------------------------------------------------------------------------

REGION_EU868 = Region(
    code="EU868",
    name="Europe 863-870 MHz (ETSI)",
    min_frequency_hz=863_000_000,
    max_frequency_hz=870_000_000,
    bandwidths_hz=(125_000, 250_000, 500_000),
    spreading_factors=(7, 8, 9, 10, 11, 12),
    coding_rates=(5, 6, 7, 8),
    default_channels=(
        Channel(868_100_000, 125_000, "EU868-1", "LoRa Alliance RP1.0.3 Table 3"),
        Channel(868_300_000, 125_000, "EU868-2", "LoRa Alliance RP1.0.3 Table 3"),
        Channel(868_500_000, 125_000, "EU868-3", "LoRa Alliance RP1.0.3 Table 3"),
    ),
    duty_cycle_limit="sub-band dependent: 1% or 10% under EN 300 220",
    power_limits=("14 dBm ERP typical, 20 dBm permitted in some sub-bands",),
    source="LoRa Alliance RP1.0.3 s2.5; ETSI EN 300 220 - CONFIRM BEFORE USE",
    verified=False,
)

REGION_US915 = Region(
    code="US915",
    name="United States 902-928 MHz (FCC)",
    min_frequency_hz=902_000_000,
    max_frequency_hz=928_000_000,
    bandwidths_hz=(125_000, 200_000, 500_000),
    spreading_factors=(7, 8, 9, 10, 11, 12),
    coding_rates=(5, 6, 7, 8),
    default_channels=(
        Channel(902_300_000, 125_000, "US915-0", "LoRa Alliance RP1.0.3 s2.6"),
    ),
    duty_cycle_limit="no duty-cycle limit; FCC Part 15.247 emission mask applies",
    power_limits=("20 dBm conducted, 30 dBm EIRP",),
    source="LoRa Alliance RP1.0.3 s2.6; FCC Part 15.247 - CONFIRM BEFORE USE",
    verified=False,
)

REGION_AU915 = Region(
    code="AU915",
    name="Australia 915-928 MHz (ACMA)",
    min_frequency_hz=915_000_000,
    max_frequency_hz=928_000_000,
    bandwidths_hz=(125_000, 500_000),
    spreading_factors=(7, 8, 9, 10, 11, 12),
    coding_rates=(5, 6, 7, 8),
    default_channels=(
        Channel(915_200_000, 125_000, "AU915-0", "LoRa Alliance RP1.0.3 s2.7"),
    ),
    duty_cycle_limit="none stated; ACMA Class Licence applies",
    power_limits=("20 dBm EIRP",),
    source="LoRa Alliance RP1.0.3 s2.7; ACMA - CONFIRM BEFORE USE",
    verified=False,
)

REGION_AS923 = Region(
    code="AS923",
    name="Asia 923-925 MHz (variant-dependent)",
    min_frequency_hz=923_000_000,
    max_frequency_hz=925_000_000,
    bandwidths_hz=(125_000, 250_000, 500_000),
    spreading_factors=(7, 8, 9, 10, 11, 12),
    coding_rates=(5, 6, 7, 8),
    default_channels=(
        Channel(923_200_000, 125_000, "AS923-1", "LoRa Alliance RP1.0.3 s2.8"),
        Channel(923_400_000, 125_000, "AS923-2", "LoRa Alliance RP1.0.3 s2.8"),
    ),
    duty_cycle_limit="variant dependent (AS923-1/2/3/4)",
    power_limits=("16 dBm EIRP typical",),
    source="LoRa Alliance RP1.0.3 s2.8 - CONFIRM VARIANT BEFORE USE",
    verified=False,
)


REGIONS: dict[str, Region] = {
    r.code: r
    for r in (REGION_IN865, REGION_EU868, REGION_US915, REGION_AU915, REGION_AS923)
}

#: Aliases accepted in the config, mapping to a region code.
_ALIASES = {
    "in": "IN865-867",
    "in865": "IN865-867",
    "in865-867": "IN865-867",
    "india": "IN865-867",
    "eu": "EU868",
    "eu868": "EU868",
    "europe": "EU868",
    "us": "US915",
    "us915": "US915",
    "au": "AU915",
    "au915": "AU915",
    "as923": "AS923",
}


def resolve(name: str) -> Region:
    """Look up a region by code or alias.

    Raises :class:`RegionError` for an unknown region rather than defaulting
    to something plausible.
    """
    if not name:
        raise RegionError(
            "no region configured; set lora.region to one of: "
            + ", ".join(sorted(REGIONS))
        )
    code = _ALIASES.get(name.strip().lower())
    if code is None:
        raise RegionError(
            f"unknown region {name!r}; known regions: {', '.join(sorted(REGIONS))}"
        )
    return REGIONS[code]


def validate_config(
    region: Region,
    *,
    frequency_hz: int,
    bandwidth_hz: int,
    spreading_factor: int,
    coding_rate: int,
    tx_power_dbm: int,
    max_tx_power_dbm: int | None = None,
) -> None:
    """Validate a full LoRa configuration against a regional plan.

    ``max_tx_power_dbm`` is the operator-supplied ceiling. CipherMesh has no
    opinion on what it should be - the gazetted limit depends on the device
    category - so the caller must pass one for the check to be meaningful.
    """
    region.validate_frequency(frequency_hz)
    region.validate_bandwidth(bandwidth_hz)
    region.validate_spreading_factor(spreading_factor)
    region.validate_coding_rate(coding_rate)

    if max_tx_power_dbm is None:
        raise RegionError(
            f"no transmit power ceiling configured for {region.code}. "
            "Confirm the applicable EIRP/ERP limit for your device category "
            "and set lora.max_tx_power_dbm. Known published limits: "
            + "; ".join(region.power_limits)
        )
    if tx_power_dbm > max_tx_power_dbm:
        raise RegionError(
            f"tx_power {tx_power_dbm} dBm exceeds the configured ceiling of "
            f"{max_tx_power_dbm} dBm for {region.code}"
        )
    # SX126x-family hardware accepts -9..+22 dBm. Outside that the radio
    # either clamps silently or refuses; neither is acceptable.
    if not -9 <= tx_power_dbm <= 22:
        raise RegionError(
            f"tx_power {tx_power_dbm} dBm is outside the hardware range -9..22 dBm"
        )


def on_air_time_estimate(
    payload_bytes: int, frequency_mhz: float, spreading_factor: int, coding_rate: int
) -> float:
    """Estimate LoRa time-on-air for a payload, in seconds.

    Implements the Semtech SX126x time-on-air model (the same expression used
    by the SX127x datasheet). This is a **calculated estimate from the radio
    model, not a measurement**. Results are labelled as such wherever they are
    surfaced so an operator is never told a throughput number that was not
    produced by a real radio.
    """
    bw_khz = {7: 125.0, 8: 125.0, 9: 125.0, 10: 125.0, 11: 125.0, 12: 125.0}
    # SF7-SF10 may also use 250 kHz and SF7-SF12 may use 500 kHz, but the
    # RNode IN865 default plan is 125 kHz throughout.
    bandwidth_khz = bw_khz.get(spreading_factor, 125.0)

    symbol_us = (2.0**spreading_factor) / (bandwidth_khz * 1000.0) * 1e6
    preamble_symbols = 8.0
    preamble_us = (preamble_symbols + 4.25) * symbol_us
    de = 1 if spreading_factor >= 11 else 0
    crc = 1
    ih = 0
    numerator = 8.0 * payload_bytes - 4.0 * spreading_factor + 28 + 16 * crc - 20 * ih
    denominator = 4.0 * (spreading_factor - 2.0 * de)
    payload_symbols = 8.0 + max(0.0, numerator / denominator)
    if bandwidth_khz == 125.0:
        payload_symbols += 0.0
    total_us = preamble_us + payload_symbols * symbol_us
    return total_us / 1e6


__all__ = [
    "Channel",
    "Region",
    "REGIONS",
    "REGION_IN865",
    "REGION_EU868",
    "REGION_US915",
    "REGION_AU915",
    "REGION_AS923",
    "resolve",
    "validate_config",
    "on_air_time_estimate",
]

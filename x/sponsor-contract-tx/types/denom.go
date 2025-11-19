package types

// SponsorshipDenom defines the single supported base denomination for
// sponsorship limits and fee accounting within the sponsor module.
// Centralizing the denom avoids hard-coded string usage across the codebase.
const SponsorshipDenom = "peaka"
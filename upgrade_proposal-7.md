## Network upgrade to address voting power overflow risk

In the current version `0.3.0`, there is an overflow risk in the calculation of `voting power`. This is primarily due to the value of `DefaultPowerReduction` being a constant of 10^6, while the token precision on vota-ash network is 18. As a result, the actual calculated voting power is inflated by a factor of 12, leading to a potential overflow and causing consensus failures. To address this issue, this upgrade proposal introduces two solutions:
* Modify the value of `DefaultPowerReduction` from 10^6 to 10^18.
* Migrate all existing validators' voting power via `upgrade handler`
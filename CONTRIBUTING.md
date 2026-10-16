# Contributing

This repository is publicly readable. Contributions are reviewed and do not by themselves create commercial-use rights. Contributions require maintainer approval. Please open a non-sensitive issue describing a change and include tests using **synthetic data**. No production telemetry, customer indicators, GeoIP dumps, credentials or malware artifacts are permitted in pull requests.

Run `python3 -m unittest discover -s tests -v` before requesting review. Do not add pip dependencies without discussing performance implications for 1 vCPU / ~1 GB RAM deployments. Follow the security checklist and do not alter `127.0.0.1` binding or disable authentication at the reverse proxy.

# GeoINT data and license

The production VPS used the **DB-IP City Lite** October 2026 offline database. That original compressed dataset and the derived real-IP CSV are intentionally **excluded** from this GitHub repository.

Provider: [DB-IP City Lite](https://db-ip.com/db/lite.php). License information: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); check the current terms for the exact downloaded edition before reuse. Attribution present in the v3.1 Atlas UI: **“Geolocation: DB-IP City Lite (October 2026), CC BY 4.0”**. Update both the attribution and the displayed version when your dataset changes. Commercial use does not remove attribution obligations.

The dashboard's offline illustrative coastline was adapted from NOAA/GSHHG reference geometry through the Basemap dataset in the earlier DEVIL v3.1 work. Review underlying map data licensing and provenance before external commercial distribution.

## Create derived CSV without committing it

Place a legally obtained `dbip-city-lite-YYYY-MM.csv.gz` outside the repo, then:

```bash
python3 tools/geo_enrich.py \
    --intelligence-db /opt/devil-intel/data/intelligence.db \
    --geo-dataset /opt/devil-intel/data/dbip-city-lite-YYYY-MM.csv.gz \
    --output /opt/devil-intel/data/geo_enrichment.csv
```

Expected input columns are **start_ip, end_ip, continent, country, region, city, latitude, longitude** (no header). Output columns: `ip,latitude,longitude,country`, containing only matched public, globally routable IP addresses from `intelligence.db`. A generated file is written atomically, and no source database is modified.

Do not confuse GeoIP hosting/registration location with the physical source of a cyberattack. Do not use the map alone as a basis for sanctions or automated blocks.

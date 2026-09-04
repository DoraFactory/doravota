# Dora Vota PQC Roadmap

Interactive anywhere-door map of the dual-track ML-DSA-65 migration.

Click the 4-D pocket (**抽出下一步**) to draw the current work card. Click a station on the map to open that node in the same card. Press `E` for ignite mode.

```bash
# from repo root
python3 -m http.server 4173
# open http://127.0.0.1:4173/docs/pqcauth/roadmap/
```

## Light a node

1. Click **点亮 / Ignite** in the header, or press `E`.
2. Open a node and use **点亮此节点 / 标为进行中 / 熄灭**.
3. Export JSON and replace `progress.json` so the team source of truth stays in git.

Nodes are grouped into numbered stages. Nodes sharing a number may progress in parallel; a later stage cannot be activated until every earlier-stage node is complete. An earlier stage cannot be reset while a later stage remains active.

The featured design article is configured through `featuredArticle` in `data.js`.

Local curator edits live in `localStorage` and override `progress.json` on that browser. Use **恢复默认 / Reset** to drop the override and reload `progress.json`.

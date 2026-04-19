# Artemis Development To-Do

## Active Sprint — v1.1 (Next Release)

### Queue & Matchmaking
- [ ] Fix queue read — accurately detect when actively searching vs. sitting in menu
- [ ] Verify matchmaking attempt visibility during queue phase
- [ ] Detect and display lobby player count if visible in network traffic

### Match Data
- [ ] Add game type detection (Arena, BTB, Ranked, Fiesta, etc.)
- [ ] Add win/loss outcome tracking
- [ ] Increase emoji visibility (contrast/size)

### Installer & Permissions
- [ ] Configure setup.exe to install Artemis with "Run as administrator" privilege level

### Window & UI Options
- [ ] Add "Always on Top" toggle
- [ ] Add fullscreen formatting support
- [ ] Add compact/minimal mode (core server lock only, collapsible)
- [ ] Add window layout preferences (save/restore position and size)

---

## Backlog — v1.2

### VPN & Network Analysis
- [ ] Collect dataset with VPN enabled
- [ ] Analyze if VPN averages out connection or pushes to favor best server
- [ ] Document methodology (time of day, game mode, location controls)

### Stats Integration
- [ ] Research Leafapp API re-integration for full post-match stats
- [ ] Investigate server "favoritism" correlation (kills vs. hard network data)
- [ ] Add CSV export for match history

### Automation
- [ ] Built-in auto-update checker

---

## Backlog — v1.3

### GUI Overhaul
- [ ] Redesign to feature-rich 3D interface

### Customization
- [ ] Dark/light theme toggle
- [ ] Additional window layout presets

---

## Future / Ideas

- [ ] Connection quality trends over time
- [ ] Regional matchmaking bias detection
- [ ] Discord Rich Presence integration
- [ ] OBS overlay support
- [ ] Linux support (npcap alternatives)
- [ ] Web dashboard for historical stats
- [ ] Ping heatmap visualization
- [ ] Server quality rating system
- [ ] Pre-match server prediction

---

## Completed

### v1.0 (Beta)
- [x] Real-time Azure datacenter detection
- [x] Basic match history logging
- [x] VPN detection
- [x] UDP packet capture engine

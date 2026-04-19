===============================================================
  ARTEMIS   by Arkitexe
  Halo Infinite server tracker  |  Beta
===============================================================


1. WHAT IS ARTEMIS?
-------------------

Artemis is a small Windows app that tells you exactly which
Microsoft Azure data center your current Halo Infinite match
is being hosted on, the moment you connect.

When you launch Halo and hit Play, the game picks a server
somewhere on Microsoft's cloud -- could be Virginia, Iowa,
Texas, California, or anywhere around the world. Halo itself
never shows you this. If you've ever played a match and felt
"something feels off with the connection," there's a decent
chance you got sent to a server across the country or overseas.

Artemis watches the same network traffic your computer is
already producing and tells you in plain English: "You're on
Texas, USA (South Central US)" -- along with the server's IP
address and a live readout of the connection quality.

It does not:
  - Modify Halo in any way
  - Read or write Halo's memory
  - Inject into the game process
  - Send any data anywhere on the internet
  - Change matchmaking or affect gameplay

It just watches the packets going in and out of your PC.


2. WHAT YOU SEE
---------------

The app looks like a retro green-phosphor computer terminal in
a beige plastic case. That's intentional -- it was built for
fun in addition to function.

At the top:  Two animated GIFs (one triumphant, one salty)
             and the Artemis title bar.

Middle:      Current status. Either "SCANNING FOR HALO,"
             "MATCHMAKING," or a big "SERVER LOCKED" message
             with the city + state + Azure region when you're
             in a real match.

Bottom:      Match History. Every real match you play gets
             logged here with:
               - Match number + random grunt emoji
               - Location (city, USA)
               - Duration
               - A random Halo grunt quote (493 of them)
               - Server IP + any secondary "peer" endpoints
                 Halo briefly touched during that match

Footer:      Four toggle buttons:
               [ LOG ATTEMPTS ]  -- if ON, queue allocation
                   attempts (near-matches that didn't stick)
                   also get written to the log file for later
                   inspection.
               [ LIVE STATS ]    -- if ON, shows packets-per-
                   second, bytes-per-second, estimated RTT,
                   jitter, and packet-size histogram for the
                   current server. Useful during a match to
                   see how the connection is actually behaving.
               [ LEGEND ]        -- if ON, shows what each
                   type of network endpoint means (game server
                   vs. matchmaking beacon vs. Xbox Live auth
                   traffic, etc.).
               [ CHECK FOR UPDATES ] -- pulls the latest Azure
                   IP-to-region mapping from Microsoft's public
                   download page. Microsoft publishes updates
                   weekly. Not critical to run often.


3. HOW TO USE IT
----------------

1. Launch Artemis (from the Start Menu or Desktop shortcut).
   Windows will prompt for administrator access. Accept it --
   the app needs admin to see UDP packet contents (more on
   why below, under "The Boring Technical Details").

2. Start Halo Infinite and queue for a match as normal.

3. While you're in the matchmaking queue, Artemis will show
   "MATCHMAKING" and a list of how many regions it's probing.
   This is normal.

4. The moment a real match starts, the status panel will flip
   to "SERVER LOCKED" with the city and region. The match
   gets added to the history panel below.

5. When the match ends, the entry in the history gets marked
   [ENDED] and the duration is filled in. A random grunt
   quote and emoji get attached.

6. The app stays running in the background while you play
   more matches. Leave it open for as long as you want.


4. WHERE YOUR LOGS GO
---------------------

Everything Artemis writes lives in a single folder on your
Desktop called:

    Artemis Logs

Inside that folder:

    artemis.log
        The main live log. Every event gets appended here as
        it happens. Safe to open while the app is running.

    endpoint_trace.jsonl
        Technical: one JSON record per polling cycle, useful
        for debugging if something weird happens. You don't
        need to look at this unless somebody asks you to send
        it to them.

    Daily Logs/
        One file per day, named artemis_2026-04-18.log etc.
        Each match you play gets a full block in here with
        every server connection observed during the match,
        packet statistics, and a human-readable summary.

    Azure Cache/
        Microsoft's published Azure IP-to-region mapping.
        Updated when you click [ CHECK FOR UPDATES ]. You
        never need to touch this.

Nothing Artemis writes is sent to anybody -- it all stays
on your PC. The logs are yours to keep or delete. Even if
you uninstall Artemis, the logs stay put by design (in case
you want your match history back).


5. PRIVACY
----------

Artemis has zero network activity of its own, with ONE
exception: when you click [ CHECK FOR UPDATES ], the app
contacts Microsoft's public download page at
microsoft.com/en-us/download/details.aspx?id=56519 to
download the latest Azure IP-to-region data file. That's
the same thing a web browser does when you open that page.

No analytics. No telemetry. No account or login. No uploads.
Everything observed about your matches stays on your PC.


6. THE BORING TECHNICAL DETAILS
-------------------------------

For the curious. Safe to skip.

What's running under the hood:

* Python 3.11+ is the language Artemis is written in. The
  build you got was packaged with PyInstaller, which bundles
  Python and all its dependencies into a single Artemis.exe
  so you never need to install Python yourself.

* Tkinter + Pillow draw the retro terminal GUI. Pillow does
  the heavy lifting for the 3D-looking beige bezel, the
  phosphor screen glow, the scanlines, and the animated GIFs.

* psutil reads Windows' TCP connection table to discover
  which remote servers Halo is talking to. This is a read-
  only operation and doesn't need special permissions.

* WinDivert (via pydivert) is the reason Artemis asks for
  administrator access on launch. WinDivert is a Windows
  Filtering Platform driver, similar to what firewalls use,
  and it's the only reliable way on Windows to observe UDP
  packet contents -- because UDP is connectionless, the
  usual psutil/netstat interfaces can't see UDP remote
  addresses. WinDivert sees them at the kernel level.
  On first launch, the WinDivert driver installs itself
  silently. It works alongside your antivirus and firewall
  without interfering. Lots of other tools use it.

* The Microsoft Azure ServiceTags JSON is a public data
  file Microsoft publishes weekly listing every IP range
  they own and which region it's in. Artemis uses it to
  translate a raw IP address into "Virginia, USA (East US)"
  etc. The file is bundled inside Artemis.exe so it works
  offline. The [ CHECK FOR UPDATES ] button refreshes it.

How a match is actually detected:

Halo Infinite's game servers run on Azure, listening on UDP
ports 30000-31000. When your Halo client connects to one,
packets start flowing between you and that server. Artemis
watches for:

    Condition 1:  UDP packets to/from an Azure-owned IP
                  on a port in the 30000-31000 range

    Condition 2:  That packet flow sustains at least
                  5 packets per second for at least
                  15 consecutive seconds

    Condition 3:  At least 75 packets have been exchanged
                  cumulatively

When all three are true, Artemis declares a match confirmed
and locks onto that server. The thresholds are deliberately
conservative -- short probe bursts during matchmaking (when
Halo briefly pings multiple candidate servers to find the
fastest) don't meet them, so they don't get mistakenly
logged as real matches.

When all traffic to that server stops, the match is marked
ended and the duration is written to the log.


7. FAQ / TROUBLESHOOTING
------------------------

"Windows SmartScreen is warning me about the installer."

    This is expected -- Artemis is an unsigned Beta. Click
    "More info" and then "Run anyway." If you'd rather not,
    don't install it -- the author's feelings won't be hurt.

"UAC prompts every time I launch."

    Yes, that's by design. UDP packet capture requires
    admin. If you launched from an existing admin shell,
    you won't see the prompt.

"The app window is too small and I can't see everything."

    Drag the bottom-right corner to resize. The minimum size
    is set so all the toggle buttons are always visible.

"It says 'UDP: pydivert not available' at the bottom."

    Something's wrong with the WinDivert driver. Try running
    the app as administrator. If that doesn't fix it, your
    antivirus may have quarantined WinDivert64.sys. Check
    your AV's quarantine and whitelist that file.

"My match duration shows 0m 03s and [QUICK MATCH]."

    That's a real match that ended very quickly -- maybe a
    backed-out lobby or an early disconnect. The app is
    telling you it was real (unlike allocation attempts,
    which never reach the match history at all).

"I see 'PEER' entries under a match. What are those?"

    During matchmaking, Halo sometimes briefly touches
    multiple candidate servers before settling on one. The
    server you actually played on is marked "LOCKED"; the
    others show as "PEER (not match server)". They're
    displayed for transparency -- so you can see the full
    picture of what the matchmaker tried.

"Does this get me banned?"

    Artemis does not touch Halo's process, does not modify
    the game, and sits at the network stack layer completely
    separate from the game. There is no known interaction
    with anti-cheat systems. That said, any third-party tool
    alongside any multiplayer game is inherently at your own
    risk. Use at your discretion.

"How do I uninstall?"

    Start Menu > find Artemis > "Uninstall Artemis." Or
    through Windows Settings > Apps > Artemis > Uninstall.
    Your logs on the Desktop are preserved -- delete them
    manually if you don't want them.

"I found a bug / the app did something weird."

    Please save the contents of Desktop\Artemis Logs\ and
    send them to Arkitexe. The endpoint_trace.jsonl file
    plus the current daily log is enough to reconstruct
    exactly what happened.


===============================================================
  Built by Jay Willis / Arkitexe
  gamertag JayBirdofDeath
===============================================================

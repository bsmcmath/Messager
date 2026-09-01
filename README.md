# Messager

A small self-contained message-board server written in C++ (no external
libraries). It runs on this PC, is used from a web browser, and is controlled
from a native desktop app. Supports user accounts, discussion threads,
reading/posting messages, clickable links, and admin/moderation.

## The programs
- **`MessagerAdmin.exe`** — the desktop **control panel** (recommended). Hosts the
  server in-process (no terminal needed), shows the **public IP** people connect
  to, and gives you the full client plus moderation tools. **This replaces the
  old server terminal.**
- **`MessagerClient.exe`** — the desktop **client** for people who just want to
  chat. It shows the exact same interface as opening the site in a browser. The
  server address is set in a **Settings** popup (not an address bar), and a red
  bar appears only when the server can't be reached. Needs the Microsoft Edge
  WebView2 Runtime, which is preinstalled on Windows 11.
- `Messager.exe` — an optional headless console version that just runs the
  server (same engine, no GUI). Handy for running minimized/at startup.

## Files
- `admin.cpp` — the desktop control panel (Win32 GUI).
- `client.cpp` — the desktop client (Win32 + Edge WebView2).
- `server.cpp` — the headless console server.
- `messager_core.h` — shared engine (HTTP server, web UI, accounts, moderation).
- `voice_engine.h` — native voice engine (WASAPI capture/playback + Opus + UDP),
  compiled into the client.
- `voice_loopback.cpp` / `voice_net.cpp` — standalone voice test tools
  (`VoiceLoopback.exe` = hear yourself; `VoiceNet.exe` = two-machine voice test).
- `sdk/` — the WebView2 SDK and Opus (`sdk/opus`) headers + static libs.
- `messager.ico`, `messager.manifest`, `res_*.rc` — app icon, manifest, and
  version-info resources embedded in every exe.
- `build.bat` — rebuild all three exes.
- `Start Messager.bat` — launch the control panel.
- `Start Client.bat` — launch the desktop client.
- `messager_data.txt` — threads & messages (auto-created).
- `messager_users.txt` — accounts; passwords are salted + PBKDF2-hashed.
- `messager_admin.cfg` — the control panel's last-used port.
- `messager_client.cfg` — the client's last-used server address.
- `messager_client_login.dat` — the client's remembered login (DPAPI-encrypted).

## Windows security (firewall / antivirus / SmartScreen)
Each exe is built with an **app icon, version info, and an application manifest**
(company/product/description, `asInvoker`, supported-OS list). Proper metadata
like this is what antivirus heuristics look for, so a bare unknown binary is far
more likely to be flagged than these are. The control panel also **best-effort
registers a Windows Firewall inbound rule** for itself on startup (it silently
does nothing unless it happens to be run as admin).

Honest limits without a paid **code-signing certificate**:
- **SmartScreen** ("Windows protected your PC" on a freshly downloaded exe) can't
  be bypassed by metadata — only by signing (or the user clicking *More info →
  Run anyway*). Reputation also builds over time.
- The server's one-time **firewall "Allow"** prompt (for inbound connections)
  needs an admin click unless the rule is pre-added. To pre-add it yourself, run
  this once in an **Administrator** terminal:

  ```bat
  netsh advfirewall firewall add rule name="Messager Server" dir=in action=allow program="%USERPROFILE%\OneDrive\Desktop\Messager\MessagerAdmin.exe" enable=yes
  ```
- The **client** only makes outbound connections, so it doesn't trigger a firewall
  prompt at all.

## Run it
Double-click **`Start Messager.bat`** (or `MessagerAdmin.exe`). It **auto-starts
the server on the last port you used** (8080 the first time) and fetches your
public IP. Change the port in the box, click **Apply**, and that port is
remembered for next launch.

### The control panel
- **Top bar:** Start/Stop server, port, **Open in browser**, **Users &
  moderation**, and a live status line (`RUNNING on port 8080 | accounts | online`).
- **Connect URL:** the shareable `http://<your-public-ip>:<port>/` — click
  **Copy link** to share it.
- **Left:** threads (click to open; type a title + **Create** for a new one).
- **Center:** messages in the selected thread, with a box to **Post**.
- **Account:** the panel posts as a real account, just like browser users. Click
  **Sign in / Create account** to log in or make an account; the strip shows
  **Posting as @you** once signed in. You must be signed in to create threads or
  post (the first account created becomes an admin).
- **Bottom:** live server log (logins, new threads, deletions, etc.).
- **Minimize to tray:** minimizing the window tucks it into the Windows 11
  **hidden-icons** area (the ^ chevron by the clock) and the server keeps
  running. Double-click the tray icon to reopen, or right-click it for
  **Open / Quit**. (Closing with the X still quits.)

### Moderation
- **Right-click a thread or message** → **Pin / Unpin** or **Delete** it.
- **Users & moderation** button → a window listing every account where you can
  **Ban / Unban**, **Make admin / Remove admin**, or **Delete** a user.
- The **first account to register becomes an admin** and gets pin + delete
  (trash) buttons inside the browser UI too. You can promote others from the
  Users window.
- **Pinned** threads and messages sort to the top and are marked (📌 in the
  panel, a highlighted row with a pin icon in the browser).

## Voice chat (desktop client only)
Each thread has a **voice room**. In the desktop client, open a thread and click
**Join voice** (below the message box) to talk with others who joined the same
thread; **Mute** toggles your mic, **Leave voice** disconnects. The button only
appears in `MessagerClient.exe` (browsers can't do the native audio).

How it works: the client captures your mic, encodes it with **Opus**, and sends
it over **UDP to the server**, which relays it to everyone else in the room (and
mixes what you receive) — no peer-to-peer, no STUN/TURN, no third party, and the
audio is Opus over your own server. Voice uses the **same port number** as the
web server, but over **UDP**, so for voice across the internet add one more
port-forward rule: **UDP** on that port → this PC (you already forward TCP).

Use a **headset** — there's no echo cancellation yet, so open speakers will feed
back into the mic.

## The desktop client (`MessagerClient.exe`)
For people who'd rather run an app than open a browser. It embeds the live page
in a window, so the layout and features are identical to the browser — no toolbar,
just the chat.

- **Default server:** `http://47.26.185.125:100/`. Change it in **Settings**
  (right-click the title bar → *Settings…*, or the **Settings** button on the
  offline bar). Type the address, click **Save & Connect**. It's remembered in
  `messager_client.cfg`.
- **Offline indicator:** a red bar appears **only** when the server can't be
  reached, with **Retry** and **Settings** buttons. When the server is up, there's
  no bar at all.
- **Remembered login:** after you sign in once, the client stores your account
  (encrypted with Windows DPAPI in `messager_client_login.dat`) and signs you in
  automatically next time — even if the server has restarted. Signing out forgets
  it. Browsing still works without signing in; the login is just so you can post.
- The window menu also has **Reload**.

Hand this exe (plus the WebView2 Runtime, which ships with Windows 11) to anyone
you want to chat with; they can keep the default or point it at another server.

## Browser clients (what your users see)
Anyone who opens the URL sees the board immediately and can **read every thread
and message without an account**. Signing in is required only to **create threads
or post messages** — a "Sign in" button sits in the top bar, and trying to post
while signed out opens a sign-in box. Links in messages are clickable; admins get
pin + trash buttons.

A **password is optional** when registering — an account can be created with a
blank password (it then logs in with the username and an empty password).

The desktop client (below) **remembers your last sign-in** and logs you in
silently on launch, so you land ready to post.

Other browser niceties: a **light/dark toggle** (🌙/☀️, top-right, remembered per
browser), **Enter** sends a message while **Shift+Enter** adds a new line, and
admins get **pin** and **trash** buttons on threads and messages.

### Who's online
The status line's **online** count shows how many distinct accounts are
currently connected. Browsers send a lightweight "still here" ping every few
seconds; when someone closes their tab, their session drops within ~30 seconds
(or immediately, if the browser delivers the on-close signal). Signing into the
same account from several places counts as **one** person, and the control panel
itself is not counted as a visitor.

## Letting people join over the internet (port forwarding)
1. **Windows Firewall:** click *Allow* the first time the app networks (or add an
   inbound rule for the TCP port).
2. **Router port forwarding:** forward external port `8080` → this PC's LAN IP →
   internal port `8080` (TCP). Reserve a static LAN IP so the rule sticks.
3. **Share your public IP:** it's shown in the control panel's Connect URL. Give
   people `http://<that-ip>:8080/`.

### Important caveats
- **No HTTPS.** Port forwarding serves plain `http://`, so logins are
  **unencrypted in transit**. Fine for friends/testing; for encryption without
  buying a domain, run it behind a free HTTPS tunnel (e.g. Cloudflare Tunnel).
- **Your public IP can change** (many home ISPs rotate it) — re-check it in the
  panel if the link stops working. A free dynamic-DNS hostname avoids this.
- **CGNAT:** some ISPs don't hand out a real public IP, which blocks port
  forwarding. If the panel's IP doesn't match your router's WAN IP, use a tunnel.
- Keep this PC on and the app running for others to connect.

## Rebuild after editing
```bash
build.bat
```

## Reset
Delete `messager_data.txt` (threads/messages) and/or `messager_users.txt`
(accounts).

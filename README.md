# LRMDS Inventory

This workspace includes a shared LRMDS web portal that modernizes the original desktop-only inventory tool without deleting the legacy source.

The shared portal uses pure Python on the backend plus HTML and CSS on the frontend, so it runs without Flask or other external web packages.

## What changed

- The original PyQt desktop app stored data in CSV files and only worked for one person at a time.
- The new portal keeps the same resource information fields:
  - Title
  - Author/Writer
  - Grade Level
  - Program
  - Subject
  - Date Validated
  - Category
  - Remarks
- Teachers can sign in and submit records.
- The LRMDS manager can review, approve, revise, export, back up, restore, and manage user access.
- Teacher edits automatically return entries to `Pending Review` so reviewed content is re-checked after changes.
- Managers can open a full item details page to review remarks and history before changing status.
- Managers can reset a teacher password and force a password change on the next login.

## Safety features included

- Passwords are hashed with PBKDF2 instead of being stored in plain text.
- The initial manager password is written to a host-only setup note instead of being shown on the login page.
- Separate manager and teacher roles reduce accidental over-access.
- CSRF tokens protect form submissions.
- Login failures trigger temporary account lockouts.
- Audit logs record sign-ins and changes.
- Sessions are stored in SQLite, so restarting the app is safer for shared use.
- Security headers reduce browser-side attack surface.
- All writes use server-side validation and parameterized SQL.
- Users created by the manager must change their temporary password.
- Managers can create timestamped database backups and restore older snapshots.

## Files

- `portal_server.py`: shared web server and application logic
- `static/portal.css`: responsive interface styling
- `import_legacy_csv.py`: imports old CSV exports into the shared database
- `start_portal.bat`: starts the portal in LAN mode for the host computer and other computers on the same network
- `allow_inventory_network_access.bat`: creates the Windows firewall rule for port `80`
- `portal_data/inventory_portal.db`: shared SQLite database created on first run
- `portal_data/manager_setup.txt`: one-time manager sign-in note created on first run
- `portal_data/backups/`: timestamped database backups created by the manager

## Start the portal

1. Run `allow_inventory_network_access.bat` as Administrator once.
2. Double-click `start_portal.bat`.
3. On the host computer, open the URL shown in the portal startup window.
4. On other computers on the same network, open the LAN URL shown in the portal startup window, for example `http://192.168.1.58`.
5. Send that LAN URL to other users.

## First manager sign-in

On the first launch only:

1. Open `portal_data/manager_setup.txt` on the host computer.
2. Sign in with the username and temporary password written there.
3. Change the password immediately when prompted.
4. Delete `portal_data/manager_setup.txt` after the password has been changed.

## Daily manager tools

- Use `Backups` in the portal to create a fresh backup before imports or major edits.
- Every restore automatically creates a safeguard backup of the current database first.
- Use `Audit Log` filters to narrow down activity by search text, user, or scope.

## Import old CSV data

Example:

```powershell
& 'C:\Users\erdse\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\import_legacy_csv.py 'C:\Path\To\educational_inventory1.csv'
```

Imported legacy rows are marked as `Approved` so they can appear immediately in the shared portal.

## Important note for larger deployments

This version is a strong local-network portal for a school office or campus setup. For full public internet deployment, add HTTPS and move the database to a production server such as PostgreSQL behind a reverse proxy.

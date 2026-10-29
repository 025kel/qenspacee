[README.md](https://github.com/user-attachments/files/34145723/README.md)
# QenSpace Solutions and Mobile Repairs — Node.js Shop Management System

This is a server-backed first release intended for a small shop. It replaces browser-only prototype storage with a Node.js/Express API and SQLite database. Admin and attendant permissions are checked on the server, passwords are hashed with bcrypt, and browser sessions are stored in SQLite.

## Included

- Secure sign-in, sign-out, hashed passwords, administrator/attendant roles, and login rate limiting.
- Admin user creation, activation/deactivation, and password reset.
- Branded inventory with SKU, category, brand, variant, buying cost, selling price, quantity and reorder level.
- Starter catalogue covering Amaya, Oraimo, Samsung, generic chargers and earphones, phone-model tempered glass, cables, covers, power banks, adapters and memory cards.
- Sales/POS, server-side stock deduction, receipt numbers and printable receipts.
- Phone repair jobs, quotations, payments recorded against jobs, and status updates.
- Manual M-Pesa agent transaction log, including reference, transaction type, amount and commission. This does not connect to Safaricom.
- Admin-only expenses, reports, audit log and JSON data backup download.
- Responsive interface for phones, tablets and desktop browsers.

## Run locally on Windows, macOS or Linux

1. Install Node.js 20 LTS or newer from https://nodejs.org/.
2. Extract this folder to a normal folder, for example `C:\qenspace`.
3. Open a terminal/Command Prompt in that folder.
4. Install packages:

   ```bash
   npm install
   ```

5. Copy `.env.example` to a new file named `.env`.
6. Edit `.env` and set a unique administrator password of at least 12 characters and a long random session secret. Example settings for local development:

   ```env
   NODE_ENV=development
   PORT=3000
   SESSION_SECRET=replace-this-with-a-unique-random-secret-of-40-or-more-characters
   DB_PATH=./data/qenspace.sqlite
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=use-a-unique-password-of-at-least-12-characters
   SHOP_NAME=QenSpace Solutions and Mobile Repairs
   ```

   Do not use the example password in a live deployment. The initial administrator is created only when the users table is empty. If the database was already initialized without an admin password, set the variables and restart; the admin will be created while there are no users.

7. Start the application:

   ```bash
   npm start
   ```

8. Visit http://localhost:3000. Sign in using the `ADMIN_USERNAME` and `ADMIN_PASSWORD` values you configured. From Staff Accounts, create an attendant account with a different strong password.
9. Open Inventory or Settings and choose **Add starter catalogue**. The product prices and quantities are illustrative; edit them to match your supplier prices and physical stock.

The application creates its SQLite database at `DB_PATH`. Keep that database file private; it contains business records and password hashes.

## Hosting online (Render + persistent disk)

This app uses SQLite, so it needs a persistent disk. Do not deploy it to an ephemeral filesystem and assume records will survive restarts.

1. Create a private GitHub repository and upload the contents of this folder. Do not upload `.env`, the `data` folder, database files or `node_modules`.
2. In Render, create a **Web Service** from the repository.
3. Set:
   - **Build command:** `npm install`
   - **Start command:** `npm start`
4. Add a persistent disk to the service:
   - **Mount path:** `/var/data`
   - Choose a size appropriate for the shop's records and plan.
5. Add environment variables in the Render dashboard:
   - `NODE_ENV` = `production`
   - `PORT` = use the platform-provided port; if the platform requires an explicit value, set the value it documents.
   - `DB_PATH` = `/var/data/qenspace.sqlite`
   - `SESSION_SECRET` = a unique random secret at least 32 characters long
   - `ADMIN_USERNAME` = your preferred administrator username
   - `ADMIN_PASSWORD` = a unique strong password of at least 12 characters
   - `SHOP_NAME` = `QenSpace Solutions and Mobile Repairs`
6. Deploy. Open the hosted HTTPS URL and sign in with the administrator credentials configured above.
7. Create attendant accounts inside **Staff Accounts**. Change passwords if staff leave or access changes.
8. Add the starter catalogue, verify product prices and quantities, and test sales/receipts using sample data before entering real transactions.
9. In Settings & Audit, download a JSON backup regularly. Store it somewhere secure, separate from the hosting account, and periodically verify that you can retrieve it.

Render's menus and pricing may change. Review the hosting provider's current persistent disk and web-service documentation before committing to a paid plan. A single-instance SQLite deployment is suitable for a small shop MVP, but it is not intended for horizontal scaling or several concurrent application instances. If you need high availability or multiple app instances, migrate to managed PostgreSQL and a shared session store before scaling.

## Security and production checklist

- Set a unique, long `SESSION_SECRET` and strong admin password; never commit `.env` to GitHub.
- Enforce HTTPS (the hosting platform should terminate TLS); use a persistent disk for SQLite.
- Restrict access to the hosting account and downloaded backups.
- Take and test backups before migrating data or changing infrastructure.
- Create separate user accounts; never share admin credentials.
- Test account deactivation, stock deductions, duplicate SKU handling, receipts, repairs and backups with sample records.
- Financial totals are operational summaries, not audited accounting or tax statements. Validate the cash/float accounting model against actual agent statements.
- M-Pesa records are entered manually. No live payment verification, STK push, Safaricom API, statement import or automatic commission reconciliation is included.
- This version records repair quote/paid totals but does not maintain a separate immutable payment ledger for each repair payment. Before relying on it for formal accounting, add a transaction-level repair-payment ledger, refunds/reversals, stock movement history and reconciliation controls.
- The JSON backup includes account records and password hashes. Treat it as confidential. There is no automated off-site backup or one-click restore in this release.

## Main files

- `server.js` — Express server, database schema, authentication, authorization and API routes.
- `public/index.html` — responsive user interface for admin and attendant portals.
- `.env.example` — configuration template.

## Customer portal (added)

- Public customer page: `/customer`.
- Customers can request repair appointments, ask a technician a question, and check a request using its reference number plus the same phone number used to submit it.
- WhatsApp contact link is configured for **+254 700 776 060**.
- Signed-in staff can use **Customer Portal** in the staff dashboard to confirm/reschedule/decline appointments and respond to questions.
- Customer request tables are created automatically on app startup. Existing users, password hashes, inventory, sales, repair jobs and other business records are not dropped or reset.
- JSON backup now includes `customer_appointments` and `customer_enquiries`.
- Public submissions have rate limiting and basic input validation. This MVP does not send automatic WhatsApp messages, SMS reminders, or email notifications; staff must contact customers manually. A reference and phone-number check is used for customer lookups, so customers should keep references private.

After deploying, test `/customer`, submit a test booking and question, then sign into the staff dashboard and process both. Download a new backup after testing. Do not change `DB_PATH` or reset the existing database during deployment.

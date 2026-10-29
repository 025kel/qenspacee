# QenSpace hosting checklist

- [ ] Node.js 20+ available
- [ ] `.env` configured locally; never committed
- [ ] Strong initial administrator password
- [ ] Unique `SESSION_SECRET` (32+ characters)
- [ ] `npm install` succeeds
- [ ] `npm start` works locally
- [ ] Login works and wrong password is rejected
- [ ] Admin can create an attendant account
- [ ] Attendant cannot open admin-only API routes
- [ ] Starter catalogue added; prices and quantities reviewed
- [ ] Test sale reduces stock and produces a printable receipt
- [ ] Test repair job can be created and updated
- [ ] Test manual M-Pesa transaction can be recorded
- [ ] Backup downloaded and stored securely
- [ ] Hosting has HTTPS and persistent storage mounted at `/var/data`
- [ ] Production environment variables are configured in hosting dashboard
- [ ] Hosted login and cross-device synchronization tested
- [ ] Database backup and recovery procedure tested

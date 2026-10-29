require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 3000);
if (process.env.NODE_ENV === 'production' && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error('Set SESSION_SECRET to a unique random value of at least 32 characters in production.');
}
const dbPath = process.env.DB_PATH || './data/qenspace.sqlite';
fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Database schema. Money is stored as integer cents to avoid floating-point errors.
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, display_name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','attendant')), active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT, sku TEXT UNIQUE, name TEXT NOT NULL,
 category TEXT NOT NULL, brand TEXT DEFAULT '', variant TEXT DEFAULT '',
 cost_cents INTEGER NOT NULL DEFAULT 0, price_cents INTEGER NOT NULL DEFAULT 0,
 quantity INTEGER NOT NULL DEFAULT 0, reorder_level INTEGER NOT NULL DEFAULT 5,
 active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sales (
 id INTEGER PRIMARY KEY AUTOINCREMENT, receipt_no TEXT UNIQUE NOT NULL,
 total_cents INTEGER NOT NULL, paid_cents INTEGER NOT NULL, payment_method TEXT NOT NULL,
 customer_name TEXT DEFAULT '', notes TEXT DEFAULT '', user_id INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS sale_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT, sale_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
 product_name TEXT NOT NULL, quantity INTEGER NOT NULL, unit_price_cents INTEGER NOT NULL,
 line_total_cents INTEGER NOT NULL, FOREIGN KEY(sale_id) REFERENCES sales(id),
 FOREIGN KEY(product_id) REFERENCES products(id)
);
CREATE TABLE IF NOT EXISTS repairs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_no TEXT UNIQUE NOT NULL,
 customer_name TEXT NOT NULL, customer_phone TEXT DEFAULT '', device TEXT NOT NULL,
 issue TEXT NOT NULL, quote_cents INTEGER NOT NULL DEFAULT 0, paid_cents INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'Received', notes TEXT DEFAULT '', user_id INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS mpesa_transactions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, txn_ref TEXT UNIQUE NOT NULL,
 txn_type TEXT NOT NULL CHECK(txn_type IN ('DEPOSIT','WITHDRAWAL','OTHER')),
 amount_cents INTEGER NOT NULL, commission_cents INTEGER NOT NULL DEFAULT 0,
 customer_name TEXT DEFAULT '', phone TEXT DEFAULT '', notes TEXT DEFAULT '',
 user_id INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS expenses (
 id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, description TEXT NOT NULL,
 amount_cents INTEGER NOT NULL, user_id INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL,
 details TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const cents = value => {
 const n = Number(value);
 if (!Number.isFinite(n) || n < 0) throw new Error('Enter a valid non-negative amount.');
 return Math.round(n * 100);
};
const money = n => (Number(n || 0) / 100).toFixed(2);
const log = (userId, action, details='') => db.prepare('INSERT INTO audit_log(user_id,action,details) VALUES(?,?,?)').run(userId || null, action, String(details).slice(0,500));
const safeUser = u => ({ id:u.id, username:u.username, displayName:u.display_name, role:u.role });
const adminOnly = (req,res,next) => req.session.user?.role === 'admin' ? next() : res.status(403).json({error:'Administrator permission required.'});
const signedIn = (req,res,next) => req.session.user ? next() : res.status(401).json({error:'Please sign in again.'});
const wrap = fn => (req,res,next) => { try { fn(req,res,next); } catch(e) { console.error(e); res.status(400).json({error:e.message || 'Request failed.'}); } };

// Create initial administrator only when the users table is empty. Set credentials in hosting environment variables.
if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0) {
 const username = process.env.ADMIN_USERNAME || 'admin';
 const password = process.env.ADMIN_PASSWORD;
 if (!password || password.length < 12) {
  console.warn('No secure ADMIN_PASSWORD configured. Set ADMIN_PASSWORD (12+ characters) in .env before first launch.');
 } else {
  db.prepare('INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)')
   .run(username, bcrypt.hashSync(password, 12), 'Shop Administrator', 'admin');
  console.log(`Initial administrator account created for username: ${username}`);
 }
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(session({
 name: 'qenspace.sid', secret: process.env.SESSION_SECRET || 'development-only-change-this-secret-before-hosting',
 resave: false, saveUninitialized: false,
 store: new SQLiteStore({ db: 'sessions.sqlite', dir: path.dirname(path.resolve(dbPath)) }),
 cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000*60*60*10 }
}));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (req,res) => res.json({ok:true, app:'QenSpace Shop Management System'}));
app.get('/api/me', (req,res) => res.json({user:req.session.user || null, shopName:process.env.SHOP_NAME || 'QenSpace Solutions and Mobile Repairs'}));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many sign-in attempts. Wait 15 minutes and try again.' } });
app.post('/api/login', loginLimiter, wrap((req,res) => {
 const username = String(req.body.username || '').trim();
 const password = String(req.body.password || '');
 const user = db.prepare('SELECT * FROM users WHERE username=? AND active=1').get(username);
 if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({error:'Incorrect username or password.'});
 req.session.regenerate(err => {
  if (err) return res.status(500).json({error:'Could not create session.'});
  req.session.user = safeUser(user);
  log(user.id,'LOGIN','Signed in');
  res.json({user:req.session.user});
 });
}));
app.post('/api/logout', signedIn, (req,res) => { const id=req.session.user.id; log(id,'LOGOUT','Signed out'); req.session.destroy(()=>res.json({ok:true})); });

app.get('/api/dashboard', signedIn, (req,res) => {
 const today = new Date().toISOString().slice(0,10);
 const sales = db.prepare("SELECT COALESCE(SUM(total_cents),0) n, COUNT(*) c FROM sales WHERE date(created_at)=?").get(today);
 const low = db.prepare('SELECT COUNT(*) n FROM products WHERE active=1 AND quantity<=reorder_level').get().n;
 const openRepairs = db.prepare("SELECT COUNT(*) n FROM repairs WHERE status NOT IN ('Collected','Cancelled')").get().n;
 const mpesa = db.prepare("SELECT COALESCE(SUM(commission_cents),0) n FROM mpesa_transactions WHERE date(created_at)=?").get(today).n;
 const recent = db.prepare('SELECT s.receipt_no,s.total_cents,s.payment_method,s.created_at,u.display_name FROM sales s JOIN users u ON u.id=s.user_id ORDER BY s.id DESC LIMIT 8').all();
 res.json({salesToday:money(sales.n),salesCount:sales.c,lowStock:low,openRepairs,commissionToday:money(mpesa),recent:recent.map(x=>({...x,total:money(x.total_cents)}))});
});

app.get('/api/products', signedIn, (req,res) => {
 const rows=db.prepare('SELECT * FROM products WHERE active=1 ORDER BY category,brand,name').all();
 res.json(rows.map(p=>({...p,cost:money(p.cost_cents),price:money(p.price_cents)})));
});
app.post('/api/products', signedIn, adminOnly, wrap((req,res) => {
 const b=req.body; const name=String(b.name||'').trim(); if(!name) throw new Error('Product name is required.');
 const info=db.prepare(`INSERT INTO products(sku,name,category,brand,variant,cost_cents,price_cents,quantity,reorder_level)
 VALUES(?,?,?,?,?,?,?,?,?)`).run(String(b.sku||'').trim()||null,name,String(b.category||'Other'),String(b.brand||''),String(b.variant||''),cents(b.cost),cents(b.price),Math.max(0,parseInt(b.quantity||0,10)),Math.max(0,parseInt(b.reorderLevel||5,10)));
 log(req.session.user.id,'PRODUCT_CREATED',name); res.status(201).json({id:info.lastInsertRowid});
}));
app.put('/api/products/:id', signedIn, adminOnly, wrap((req,res) => {
 const b=req.body; const existing=db.prepare('SELECT id FROM products WHERE id=? AND active=1').get(req.params.id); if(!existing) throw new Error('Product not found.');
 db.prepare(`UPDATE products SET sku=?,name=?,category=?,brand=?,variant=?,cost_cents=?,price_cents=?,quantity=?,reorder_level=? WHERE id=?`)
 .run(String(b.sku||'').trim()||null,String(b.name||'').trim(),String(b.category||'Other'),String(b.brand||''),String(b.variant||''),cents(b.cost),cents(b.price),Math.max(0,parseInt(b.quantity||0,10)),Math.max(0,parseInt(b.reorderLevel||5,10)),req.params.id);
 log(req.session.user.id,'PRODUCT_UPDATED',String(b.name||'')); res.json({ok:true});
}));
app.post('/api/products/:id/stock', signedIn, adminOnly, wrap((req,res) => {
 const q=parseInt(req.body.quantity,10); if(!Number.isInteger(q)||q<1) throw new Error('Stock quantity must be a positive whole number.');
 const r=db.prepare('UPDATE products SET quantity=quantity+? WHERE id=? AND active=1').run(q,req.params.id); if(!r.changes) throw new Error('Product not found.');
 log(req.session.user.id,'STOCK_RECEIVED',`Product ${req.params.id}, quantity ${q}`); res.json({ok:true});
}));
app.delete('/api/products/:id', signedIn, adminOnly, wrap((req,res) => {
 db.prepare('UPDATE products SET active=0 WHERE id=?').run(req.params.id); log(req.session.user.id,'PRODUCT_ARCHIVED',`Product ${req.params.id}`); res.json({ok:true});
}));

app.post('/api/sales', signedIn, wrap((req,res) => {
 const items=Array.isArray(req.body.items)?req.body.items:[]; if(!items.length) throw new Error('Add at least one product to the sale.');
 const method=String(req.body.paymentMethod||'Cash'); if(!['Cash','M-Pesa','Card','Split','Credit'].includes(method)) throw new Error('Invalid payment method.');
 const create=db.transaction(()=>{
  let total=0; const lines=[];
  for(const item of items){
   const qty=Number(item.quantity); if(!Number.isInteger(qty)||qty<1) throw new Error('Each quantity must be a positive whole number.');
   const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(Number(item.productId));
   if(!p) throw new Error('A selected product is no longer available.'); if(p.quantity<qty) throw new Error(`Not enough stock for ${p.name}. Available: ${p.quantity}.`);
   const line=qty*p.price_cents; total+=line; lines.push({p,qty,line});
  }
  const paid=req.body.paidAmount===''||req.body.paidAmount==null?total:cents(req.body.paidAmount);
  if(paid>total) throw new Error('Amount paid cannot exceed the sale total.');
  const receipt='QS-'+new Date().toISOString().slice(2,10).replaceAll('-','')+'-'+Date.now().toString().slice(-6);
  const sale=db.prepare('INSERT INTO sales(receipt_no,total_cents,paid_cents,payment_method,customer_name,notes,user_id) VALUES(?,?,?,?,?,?,?)')
   .run(receipt,total,paid,method,String(req.body.customerName||''),String(req.body.notes||''),req.session.user.id);
  for(const l of lines){ db.prepare('INSERT INTO sale_items(sale_id,product_id,product_name,quantity,unit_price_cents,line_total_cents) VALUES(?,?,?,?,?,?)').run(sale.lastInsertRowid,l.p.id,l.p.name,l.qty,l.p.price_cents,l.line); db.prepare('UPDATE products SET quantity=quantity-? WHERE id=?').run(l.qty,l.p.id); }
  log(req.session.user.id,'SALE_CREATED',`${receipt}; total=${money(total)}`); return {id:sale.lastInsertRowid,receiptNo:receipt,total:money(total),paid:money(paid),balance:money(total-paid)};
 }); res.status(201).json(create());
}));
app.get('/api/sales', signedIn, (req,res) => {
 const rows=db.prepare('SELECT s.*,u.display_name FROM sales s JOIN users u ON u.id=s.user_id ORDER BY s.id DESC LIMIT 200').all();
 res.json(rows.map(s=>({...s,total:money(s.total_cents),paid:money(s.paid_cents),items:db.prepare('SELECT product_name,quantity,unit_price_cents,line_total_cents FROM sale_items WHERE sale_id=?').all(s.id).map(i=>({...i,unitPrice:money(i.unit_price_cents),lineTotal:money(i.line_total_cents)}))})));
});
app.get('/api/sales/:id', signedIn, (req,res) => {
 const s=db.prepare('SELECT s.*,u.display_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.id=?').get(req.params.id); if(!s)return res.status(404).json({error:'Sale not found.'});
 res.json({...s,total:money(s.total_cents),paid:money(s.paid_cents),items:db.prepare('SELECT product_name,quantity,unit_price_cents,line_total_cents FROM sale_items WHERE sale_id=?').all(s.id).map(i=>({...i,unitPrice:money(i.unit_price_cents),lineTotal:money(i.line_total_cents)}))});
});

app.get('/api/repairs', signedIn, (req,res) => res.json(db.prepare('SELECT r.*,u.display_name FROM repairs r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 300').all().map(r=>({...r,quote:money(r.quote_cents),paid:money(r.paid_cents),balance:money(Math.max(0,r.quote_cents-r.paid_cents))}))));
app.post('/api/repairs', signedIn, wrap((req,res) => {
 const b=req.body; for(const k of ['customerName','device','issue']) if(!String(b[k]||'').trim()) throw new Error(`${k} is required.`);
 const job='REP-'+Date.now().toString().slice(-8);
 const result=db.prepare('INSERT INTO repairs(job_no,customer_name,customer_phone,device,issue,quote_cents,paid_cents,status,notes,user_id) VALUES(?,?,?,?,?,?,?,?,?,?)')
 .run(job,String(b.customerName).trim(),String(b.customerPhone||''),String(b.device).trim(),String(b.issue).trim(),cents(b.quote||0),cents(b.paid||0),String(b.status||'Received'),String(b.notes||''),req.session.user.id);
 log(req.session.user.id,'REPAIR_CREATED',job); res.status(201).json({id:result.lastInsertRowid,jobNo:job});
}));
app.patch('/api/repairs/:id', signedIn, wrap((req,res) => {
 const allowed=['Received','Diagnosing','Awaiting Parts','In Progress','Ready for Collection','Collected','Cancelled'];
 const b=req.body; const old=db.prepare('SELECT * FROM repairs WHERE id=?').get(req.params.id); if(!old)throw new Error('Repair job not found.');
 const status=b.status?String(b.status):old.status; if(!allowed.includes(status))throw new Error('Invalid repair status.');
 const quote=b.quote==null?old.quote_cents:cents(b.quote); const paid=b.paid==null?old.paid_cents:cents(b.paid);
 db.prepare('UPDATE repairs SET status=?,quote_cents=?,paid_cents=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status,quote,paid,b.notes==null?old.notes:String(b.notes),old.id);
 log(req.session.user.id,'REPAIR_UPDATED',`${old.job_no}; status=${status}`); res.json({ok:true});
}));

app.get('/api/mpesa', signedIn, (req,res) => res.json(db.prepare('SELECT m.*,u.display_name FROM mpesa_transactions m JOIN users u ON u.id=m.user_id ORDER BY m.id DESC LIMIT 300').all().map(m=>({...m,amount:money(m.amount_cents),commission:money(m.commission_cents)}))));
app.post('/api/mpesa', signedIn, wrap((req,res) => {
 const b=req.body; const ref=String(b.reference||'').trim(); if(!ref)throw new Error('M-Pesa transaction reference is required.');
 const type=String(b.type||'').toUpperCase(); if(!['DEPOSIT','WITHDRAWAL','OTHER'].includes(type))throw new Error('Choose Deposit, Withdrawal or Other.');
 const result=db.prepare('INSERT INTO mpesa_transactions(txn_ref,txn_type,amount_cents,commission_cents,customer_name,phone,notes,user_id) VALUES(?,?,?,?,?,?,?,?)')
 .run(ref,type,cents(b.amount),cents(b.commission||0),String(b.customerName||''),String(b.phone||''),String(b.notes||''),req.session.user.id);
 log(req.session.user.id,'MPESA_RECORDED',`${ref}; ${type}; amount=${b.amount}`); res.status(201).json({id:result.lastInsertRowid});
}));

app.get('/api/expenses', signedIn, adminOnly, (req,res) => res.json(db.prepare('SELECT e.*,u.display_name FROM expenses e JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT 300').all().map(e=>({...e,amount:money(e.amount_cents)}))));
app.post('/api/expenses', signedIn, adminOnly, wrap((req,res) => {
 const b=req.body; if(!String(b.category||'').trim()||!String(b.description||'').trim())throw new Error('Expense category and description are required.');
 const r=db.prepare('INSERT INTO expenses(category,description,amount_cents,user_id) VALUES(?,?,?,?)').run(String(b.category),String(b.description),cents(b.amount),req.session.user.id);
 log(req.session.user.id,'EXPENSE_RECORDED',`${b.category}; ${b.amount}`); res.status(201).json({id:r.lastInsertRowid});
}));
app.get('/api/reports', signedIn, adminOnly, (req,res) => {
 const sales=db.prepare('SELECT COUNT(*) count,COALESCE(SUM(total_cents),0) total,COALESCE(SUM(paid_cents),0) paid FROM sales').get();
 const stock=db.prepare('SELECT COUNT(*) products,COALESCE(SUM(quantity*cost_cents),0) value,COALESCE(SUM(quantity),0) units FROM products WHERE active=1').get();
 const mpesa=db.prepare('SELECT COUNT(*) count,COALESCE(SUM(amount_cents),0) amount,COALESCE(SUM(commission_cents),0) commission FROM mpesa_transactions').get();
 const repairs=db.prepare('SELECT COUNT(*) count,COALESCE(SUM(quote_cents),0) quoted,COALESCE(SUM(paid_cents),0) paid FROM repairs').get();
 res.json({sales:{count:sales.count,total:money(sales.total),paid:money(sales.paid)},stock:{products:stock.products,units:stock.units,value:money(stock.value)},mpesa:{count:mpesa.count,amount:money(mpesa.amount),commission:money(mpesa.commission)},repairs:{count:repairs.count,quoted:money(repairs.quoted),paid:money(repairs.paid)}});
});
app.get('/api/users', signedIn, adminOnly, (req,res) => res.json(db.prepare('SELECT id,username,display_name,role,active,created_at FROM users ORDER BY id').all()));
app.post('/api/users', signedIn, adminOnly, wrap((req,res) => {
 const b=req.body; const username=String(b.username||'').trim(); const password=String(b.password||''); const display=String(b.displayName||'').trim(); const role=String(b.role||'attendant');
 if(!/^[a-zA-Z0-9_.-]{3,40}$/.test(username))throw new Error('Username must be 3–40 letters, numbers, dots, underscores or hyphens.');
 if(password.length<12)throw new Error('Password must be at least 12 characters.'); if(!display)throw new Error('Display name is required.'); if(!['admin','attendant'].includes(role))throw new Error('Invalid role.');
 db.prepare('INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)').run(username,bcrypt.hashSync(password,12),display,role); log(req.session.user.id,'USER_CREATED',`${username}; ${role}`); res.status(201).json({ok:true});
}));
app.patch('/api/users/:id', signedIn, adminOnly, wrap((req,res) => {
 const id=Number(req.params.id); if(id===req.session.user.id && req.body.active===false)throw new Error('You cannot deactivate your own account.');
 const u=db.prepare('SELECT * FROM users WHERE id=?').get(id); if(!u)throw new Error('User not found.');
 const active=req.body.active===false?0:1; db.prepare('UPDATE users SET active=? WHERE id=?').run(active,id);
 if(req.body.password){if(String(req.body.password).length<12)throw new Error('Password must be at least 12 characters.');db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(String(req.body.password),12),id);}
 log(req.session.user.id,'USER_UPDATED',`${u.username}; active=${active}`); res.json({ok:true});
}));
app.get('/api/audit', signedIn, adminOnly, (req,res) => res.json(db.prepare('SELECT a.*,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 300').all()));
app.get('/api/backup', signedIn, adminOnly, (req,res) => {
 const tables=['users','products','sales','sale_items','repairs','mpesa_transactions','expenses','audit_log'];
 const backup={app:'QenSpace Shop Management System',createdAt:new Date().toISOString(),tables:{}};
 for(const t of tables) backup.tables[t]=db.prepare(`SELECT * FROM ${t}`).all();
 res.setHeader('Content-Disposition', `attachment; filename=qenspace-backup-${new Date().toISOString().slice(0,10)}.json`);
 res.type('application/json').send(JSON.stringify(backup,null,2));
});

// Starter catalogue: illustrative KSh values; owner must verify prices and opening stock.
app.post('/api/starter-catalogue', signedIn, adminOnly, wrap((req,res) => {
 const catalogue=[
 ['CH-AM-5W','Amaya 5W Charger','Chargers','Amaya','5W USB-A',180,350,5],['CH-AM-20W','Amaya 20W Fast Charger','Chargers','Amaya','20W USB-C',350,650,5],['CH-OR-20W','Oraimo 20W Charger','Chargers','Oraimo','20W USB-C',650,1000,5],['CH-OR-33W','Oraimo 33W Fast Charger','Chargers','Oraimo','33W USB-C',850,1300,4],['CH-SA-15W','Samsung 15W Charger','Chargers','Samsung','15W USB-A/C',650,1000,4],['CH-SA-25W','Samsung 25W Charger','Chargers','Samsung','25W USB-C',900,1400,4],['CH-GEN','Generic Phone Charger','Chargers','Generic','Standard',150,300,8],
 ['EA-AM-W','Amaya Wired Earphones','Earphones','Amaya','3.5mm',150,300,8],['EA-OR-W','Oraimo Wired Earphones','Earphones','Oraimo','3.5mm',350,600,5],['EA-SA-C','Samsung USB-C Earphones','Earphones','Samsung','USB-C',500,850,4],['EA-OR-TWS','Oraimo TWS Earbuds','Earphones','Oraimo','Bluetooth TWS',1200,1800,3],['EA-GEN-W','Generic Wired Earphones','Earphones','Generic','3.5mm',100,250,10],
 ['TG-TEC','Tecno Tempered Glass','Tempered Glass','Generic','Tecno assorted models',40,100,15],['TG-INF','Infinix Tempered Glass','Tempered Glass','Generic','Infinix assorted models',40,100,15],['TG-SAM-A','Samsung Galaxy A Tempered Glass','Tempered Glass','Generic','Galaxy A series',60,150,12],['TG-ITL','Itel Tempered Glass','Tempered Glass','Generic','Itel assorted models',40,100,10],['TG-RED','Redmi Tempered Glass','Tempered Glass','Generic','Redmi assorted models',50,120,10],['TG-IP','iPhone Tempered Glass','Tempered Glass','Generic','iPhone assorted models',80,200,8],
 ['CB-USBC','USB-C Cable','Cables','Generic','USB-A to USB-C',100,250,15],['CB-LTG','Lightning Cable','Cables','Generic','USB-A to Lightning',150,350,8],['CB-MICRO','Micro USB Cable','Cables','Generic','USB-A to Micro USB',80,200,10],['PB-OR-10K','Oraimo 10000mAh Power Bank','Power Banks','Oraimo','10000mAh',1800,2500,3],['CV-TEC','Tecno Phone Cover','Phone Covers','Generic','Assorted models',80,250,12],['CV-INF','Infinix Phone Cover','Phone Covers','Generic','Assorted models',80,250,12],['CV-SAM','Samsung Phone Cover','Phone Covers','Generic','Assorted models',100,300,10],['AD-OTG','OTG Adapter','Adapters','Generic','USB-C/USB-A assorted',80,200,8],['AD-CAR','Car Charger','Chargers','Generic','Dual USB',250,500,5],['SD-32','32GB Memory Card','Memory Cards','Generic','32GB',350,600,4]
 ];
 const insert=db.prepare('INSERT OR IGNORE INTO products(sku,name,category,brand,variant,cost_cents,price_cents,quantity,reorder_level) VALUES(?,?,?,?,?,?,?,?,?)');
 const tx=db.transaction(()=>{let added=0;for(const p of catalogue){const r=insert.run(p[0],p[1],p[2],p[3],p[4],p[5]*100,p[6]*100,p[7],4);added+=r.changes;}return added;});
 const added=tx();log(req.session.user.id,'STARTER_CATALOGUE_ADDED',`Added ${added} products`);res.json({added,message:`Added ${added} new products. Prices and quantities are examples; review them before trading.`});
}));

app.use('/api', (req,res) => res.status(404).json({error:'API endpoint not found.'}));
app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT, '0.0.0.0', () => console.log(`QenSpace running on port ${PORT}`));


from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import json, sqlite3, hashlib

BASE=Path(__file__).resolve().parent
app=FastAPI(title="Nexora Technologies - Enterprise Portal")
app.mount("/static", StaticFiles(directory=BASE/"static"), name="static")
templates=Jinja2Templates(directory=str(BASE/"templates"))

DB=BASE/"data"/"nexora.db"

def db():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    return c

def init():
    c=db()
    c.execute("CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,name TEXT,price INTEGER,category TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT,password TEXT,role TEXT)")
    if c.execute("SELECT COUNT(*) FROM products").fetchone()[0]==0:
        c.executemany("INSERT INTO products(name,price,category) VALUES(?,?,?)",[
            ("CloudEdge Gateway",84999,"Cloud"),
            ("DataVault Enterprise",174999,"Data"),
            ("SecureHub Firewall",129999,"Network"),
            ("DevSuite Enterprise",59999,"Developer")
        ])
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]==0:
        c.executemany("INSERT INTO users(email,password,role) VALUES(?,?,?)",[
            ("demo@nexora.local","nexora-demo","customer"),
            ("admin@nexora.local","admin-demo","administrator")
        ])
    c.commit(); c.close()

init()

@app.get("/",response_class=HTMLResponse)
def home(request:Request):
    return templates.TemplateResponse("home.html",{"request":request})

@app.get("/solutions",response_class=HTMLResponse)
def solutions(request:Request):
    c=db(); products=c.execute("SELECT * FROM products").fetchall(); c.close()
    return templates.TemplateResponse("solutions.html",{"request":request,"products":products})

@app.get("/technology",response_class=HTMLResponse)
def technology(request:Request):
    assets=json.loads((BASE/"data"/"asset_inventory.json").read_text())
    return templates.TemplateResponse("technology.html",{"request":request,"assets":assets})

@app.get("/about",response_class=HTMLResponse)
def about(request:Request):
    return templates.TemplateResponse("about.html",{"request":request})

@app.get("/login",response_class=HTMLResponse)
def login(request:Request):
    return templates.TemplateResponse("login.html",{"request":request,"message":None})

@app.post("/login",response_class=HTMLResponse)
def do_login(request:Request,email:str=Form(...),password:str=Form(...)):
    c=db(); u=c.execute("SELECT * FROM users WHERE email=? AND password=?",(email,password)).fetchone(); c.close()
    # Deliberately simple legacy authentication flow for the lab.
    return templates.TemplateResponse("login.html",{"request":request,
        "message":"Welcome to the Nexora portal." if u else "Invalid credentials"})

@app.get("/products/{product_id}",response_class=HTMLResponse)
def product(request:Request,product_id:int):
    c=db(); p=c.execute("SELECT * FROM products WHERE id=?",(product_id,)).fetchone(); c.close()
    return templates.TemplateResponse("product.html",{"request":request,"product":p})

@app.get("/api/products")
def api_products():
    c=db(); rows=[dict(x) for x in c.execute("SELECT * FROM products").fetchall()]; c.close()
    return rows

@app.get("/api/search")
def search(q:str=""):
    # Intentionally legacy-style query handling for scanner demonstrations.
    c=db()
    try:
        rows=[dict(x) for x in c.execute("SELECT * FROM products WHERE name LIKE '%"+q+"%'").fetchall()]
    except Exception as e:
        rows={"error":str(e)}
    c.close()
    return JSONResponse(rows)

@app.get("/api/profile")
def profile(email:str="demo@nexora.local"):
    # Synthetic IDOR-style business API for a controlled lab.
    c=db(); u=c.execute("SELECT id,email,role FROM users WHERE email=?",(email,)).fetchone(); c.close()
    return dict(u) if u else {"error":"not found"}

@app.get("/admin",response_class=HTMLResponse)
def admin(request:Request):
    c=db(); users=[dict(x) for x in c.execute("SELECT id,email,role FROM users").fetchall()]; c.close()
    return templates.TemplateResponse("admin.html",{"request":request,"users":users})

@app.get("/uploads",response_class=HTMLResponse)
def uploads(request:Request):
    return templates.TemplateResponse("uploads.html",{"request":request})

@app.get("/uploads/preview")
def preview(file:str="invoice.jpg"):
    # Scanner-friendly ImageMagick/file-processing simulation marker.
    return {"processor":"ImageMagick","requested_file":file,"lab_mode":True}

@app.get("/health")
def health():
    return {"status":"operational","company":"Nexora Technologies","environment":"synthetic-vulnerable-lab"}

@app.get("/.well-known/nexora-lab")
def lab_fingerprint():
    return {
      "purpose":"controlled vulnerability assessment laboratory",
      "company":"Nexora Technologies",
      "public_stack":["Apache HTTP Server","Fuel CMS","CMS Made Simple","Magento","OpenCart","Django"],
      "application_stack":["Apache Shiro","Redis","MongoDB","phpMyAdmin"],
      "internal_stack":["Exchange","SharePoint","TeamCity","Gogs","Windows Server"],
      "infrastructure":["Pulse Connect Secure","Cisco ASA","VMware vCenter","ingress-nginx","Veeam","EasyNAS","Cacti","ManageEngine Applications Manager","Horde Webmail","Linux kernel"],
      "cve_scope":"exactly 30 shortlisted CVEs"
    }

@app.get("/lab/asset-inventory")
def inventory():
    return json.loads((BASE/"data"/"asset_inventory.json").read_text())

@app.get("/lab/cve-scope")
def scope():
    return json.loads((BASE/"data"/"cve_scope.json").read_text())

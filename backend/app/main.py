from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from .analyzer import analyze_email
from .report import make_html_report

app = FastAPI(title="SentinelAI SIH26106", version="3.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
CASES = []

@app.get("/api/health")
def health():
    return {"status":"ok","service":"sentinelai","version":"3.1"}

@app.get("/api/stats")
def stats():
    return {
        "cases": len(CASES),
        "critical": sum(x.get("risk_level")=="Critical" for x in CASES),
        "iocs": sum(len(x.get("iocs",[])) for x in CASES)
    }

@app.get("/api/cases")
def cases():
    return {"cases": CASES}

def normalize(r):
    r["risk_level"] = r.get("risk_level", r.get("severity","Low"))
    r["from"] = r.get("from", r.get("sender",""))
    r["authentication"] = r.get("authentication", r.get("auth", {}))
    r["geolocation"] = r.get("geolocation", r.get("geo", []))
    r["timeline"] = r.get("timeline", [
        {"step":i+1,"event":x} for i,x in enumerate(r.get("received_headers",[]))
    ])
    r["attachments"] = r.get("attachments", [])
    r["urls"] = r.get("urls", [])
    r["ips"] = r.get("ips", [])
    r["domains"] = r.get("domains", [])
    r["findings"] = r.get("findings", [])
    r["iocs"] = r.get("iocs", [])
    r["reply_to"] = r.get("reply_to","")
    return r

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(400, "Please upload an .eml file.")
    try:
        data = await file.read()
        if not data:
            raise HTTPException(400, "The uploaded .eml file is empty.")
        result = normalize(analyze_email(data, file.filename))
        CASES.insert(0, result)
        return result
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(status_code=500, content={"error":f"Email analysis failed: {type(e).__name__}: {e}"})

@app.post("/api/report")
async def report(file: UploadFile = File(...)):
    data = await file.read()
    try:
        return HTMLResponse(make_html_report(analyze_email(data, file.filename)))
    except Exception as e:
        raise HTTPException(500, f"Report generation failed: {e}")

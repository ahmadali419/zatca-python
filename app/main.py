from fastapi import FastAPI
from app.onboarding import run_onboarding
from app.clearance_reporting import run_clearance_reporting
from app.create_invoice import create_invoice_xml
from pydantic import BaseModel
from typing import Dict
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI()


class CSRRequest(BaseModel):
    environment_type: str
    otp: str
    csr_config: Dict[str, str]

class ReportingRequest(BaseModel):
    invoice_id:str
    invoice_data:dict

@app.post("/onboarding")
def onboarding(request: CSRRequest):    
    return run_onboarding(request.environment_type, request.otp, request.csr_config)


@app.post("/reporting")
def reporting(request: ReportingRequest):
    try:
        file_path = f"/tmp/{request.invoice_id}-invoice.xml"  # ✅ use /tmp on Vercel
        create_invoice_xml(request.invoice_data, file_path)
        return run_clearance_reporting(file_path)
    except Exception as e:
        logger.exception("Error in /reporting")
        return {"error": str(e)}

@app.get("/")
def hello():
    return {"meesage" : "hello world"}
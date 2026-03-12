from pydantic import BaseModel
from typing import Optional


class UserCreate(BaseModel):
    name: str
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class AppCreate(BaseModel):
    name: str
    version: str
    description: Optional[str] = None
    url: Optional[str] = None
    category: Optional[str] = None


class VulnCreate(BaseModel):
    vuln_id: str
    title: str
    severity: str
    vuln_type: Optional[str] = None
    http_method: Optional[str] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    description: Optional[str] = None
    code_location: Optional[str] = None
    poc: Optional[str] = None
    remediation: Optional[str] = None


class ScanCreate(BaseModel):
    scanner_name: str
    scan_date: str
    authenticated: bool = False
    is_public: bool = True
    notes: Optional[str] = None


class FindingCreate(BaseModel):
    vuln_type: str
    http_method: Optional[str] = None
    url: str
    parameter: Optional[str] = None

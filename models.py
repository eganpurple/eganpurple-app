from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    targets = relationship("ScanTarget", back_populates="owner", cascade="all, delete-orphan")
    jobs = relationship("ScanJob", back_populates="owner", cascade="all, delete-orphan")


class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    domain = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="targets")
    jobs = relationship("ScanJob", back_populates="target", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target_id = Column(Integer, ForeignKey("scan_targets.id"), nullable=False, index=True)
    scan_type = Column(String, nullable=False)
    status = Column(String, nullable=False, default="queued")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="jobs")
    target = relationship("ScanTarget", back_populates="jobs")
    results = relationship("ScanResult", back_populates="job", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    result_type = Column(String, nullable=False)
    value = Column(String, nullable=False, index=True)
    raw_output = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    job = relationship("ScanJob", back_populates="results")
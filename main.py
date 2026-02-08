appfrom fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta

from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

from jose import jwt, JWTError
from passlib.context import CryptContext

# -----------------------------
# Config
# -----------------------------

DATABASE_URL = "sqlite:////tmp/guardianshield.db"
JWT_SECRET_KEY = "godmode1224567890King$1$2$3$4"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# -----------------------------
# DB setup
# -----------------------------

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -----------------------------
# Models
# -----------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="guardian")  # guardian, admin, moderator
    created_at = Column(DateTime, default=datetime.utcnow)

    children = relationship("ChildProfile", back_populates="guardian")
    ideas = relationship("CommunityIdea", back_populates="user")


class ChildProfile(Base):
    __tablename__ = "child_profiles"

    id = Column(Integer, primary_key=True, index=True)
    guardian_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    display_name = Column(String, nullable=False)
    age_range = Column(String, nullable=True)  # child, teen, etc.
    created_at = Column(DateTime, default=datetime.utcnow)

    guardian = relationship("User", back_populates="children")
    alerts = relationship("Alert", back_populates="child")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    child_id = Column(Integer, ForeignKey("child_profiles.id"), nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_labels = Column(String, nullable=False)  # CSV of labels
    explanation = Column(Text, nullable=True)
    source = Column(String, nullable=True)
    status = Column(String, default="new")
    created_at = Column(DateTime, default=datetime.utcnow)

    child = relationship("ChildProfile", back_populates="alerts")


class CommunityIdea(Base):
    __tablename__ = "community_ideas"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String, default="new")  # new, considering, planned, implemented
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="ideas")


Base.metadata.create_all(bind=engine)

# -----------------------------
# Security helpers
# -----------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


class TokenData(BaseModel):
    user_id: Optional[int] = None


def decode_access_token(token: str) -> Optional[TokenData]:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            return None
        return TokenData(user_id=user_id)
    except JWTError:
        return None


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    token_data = decode_access_token(token)
    if token_data is None or token_data.user_id is None:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    user = db.query(User).filter(User.id == token_data.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# -----------------------------
# Schemas
# -----------------------------

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserRead(UserBase):
    id: int
    role: str
    created_at: datetime

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ChildBase(BaseModel):
    display_name: str
    age_range: Optional[str] = None

class ChildCreate(ChildBase):
    pass

class ChildRead(ChildBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True


class AlertBase(BaseModel):
    risk_score: float
    risk_labels: List[str]
    explanation: Optional[str] = None
    source: Optional[str] = None

class AlertCreate(AlertBase):
    child_id: int

class AlertRead(AlertBase):
    id: int
    status: str
    created_at: datetime

    class Config:
        orm_mode = True


class CommunityIdeaBase(BaseModel):
    title: str
    description: str

class CommunityIdeaCreate(CommunityIdeaBase):
    pass

class CommunityIdeaRead(CommunityIdeaBase):
    id: int
    status: str
    created_at: datetime
    user_id: Optional[int]

    class Config:
        orm_mode = True


class AnalyzeTextRequest(BaseModel):
    text: str
    context: Optional[str] = None
    language: Optional[str] = "en"

class AnalyzeTextResponse(BaseModel):
    risk_score: float
    risk_labels: List[str]
    explanation: str

# -----------------------------
# FastAPI app
# -----------------------------

app = FastAPI(
    title="GuardianShield Core",
    version="0.1.0",
    description="Backend API for GuardianShield safety network",
)

# ----- Auth -----

@app.post("/auth/register", response_model=UserRead)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role="guardian",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(data={"sub": user.id}, expires_delta=expires)
    return Token(access_token=token)

# ----- Children -----

@app.post("/children", response_model=ChildRead)
def create_child(
    child_in: ChildCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    child = ChildProfile(
        guardian_id=current_user.id,
        display_name=child_in.display_name,
        age_range=child_in.age_range,
    )
    db.add(child)
    db.commit()
    db.refresh(child)
    return child


@app.get("/children", response_model=List[ChildRead])
def list_children(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    children = db.query(ChildProfile).filter(ChildProfile.guardian_id == current_user.id).all()
    return children

# ----- Alerts -----

@app.post("/alerts", response_model=AlertRead)
def create_alert(
    alert_in: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    child = db.query(ChildProfile).filter(
        ChildProfile.id == alert_in.child_id,
        ChildProfile.guardian_id == current_user.id,
    ).first()
    if not child:
        raise HTTPException(status_code=404, detail="Child not found")

    labels_str = ",".join(alert_in.risk_labels)
    alert = Alert(
        child_id=child.id,
        risk_score=alert_in.risk_score,
        risk_labels=labels_str,
        explanation=alert_in.explanation,
        source=alert_in.source,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return AlertRead(
        id=alert.id,
        risk_score=alert.risk_score,
        risk_labels=alert.risk_labels.split(",") if alert.risk_labels else [],
        explanation=alert.explanation,
        source=alert.source,
        status=alert.status,
        created_at=alert.created_at,
    )


@app.get("/alerts/{child_id}", response_model=List[AlertRead])
def list_alerts_for_child(
    child_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    child = db.query(ChildProfile).filter(
        ChildProfile.id == child_id,
        ChildProfile.guardian_id == current_user.id,
    ).first()
    if not child:
        raise HTTPException(status_code=404, detail="Child not found")

    alerts = db.query(Alert).filter(Alert.child_id == child_id).all()
    results: List[AlertRead] = []
    for a in alerts:
        results.append(
            AlertRead(
                id=a.id,
                risk_score=a.risk_score,
                risk_labels=a.risk_labels.split(",") if a.risk_labels else [],
                explanation=a.explanation,
                source=a.source,
                status=a.status,
                created_at=a.created_at,
            )
        )
    return results

# ----- Community Ideas -----

@app.post("/community/ideas", response_model=CommunityIdeaRead)
def create_idea(
    idea_in: CommunityIdeaCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    title_lower = idea_in.title.lower()
    desc_lower = idea_in.description.lower()
    blocked = ["how to hack", "ddos", "botnet", "ransomware"]

    if any(b in title_lower for b in blocked) or any(b in desc_lower for b in blocked):
        raise HTTPException(
            status_code=400,
            detail="This community is for defense and protection only. Requests for hacking or illegal activity are not allowed.",
        )

    idea = CommunityIdea(
        user_id=current_user.id,
        title=idea_in.title,
        description=idea_in.description,
    )
    db.add(idea)
    db.commit()
    db.refresh(idea)
    return idea


@app.get("/community/ideas", response_model=List[CommunityIdeaRead])
def list_ideas(db: Session = Depends(get_db)):
    ideas = db.query(CommunityIdea).order_by(CommunityIdea.created_at.desc()).all()
    return ideas

# ----- AI Analyze Text -----

@app.post("/ai/analyze-text", response_model=AnalyzeTextResponse)
def analyze_text(req: AnalyzeTextRequest):
    text = req.text.lower()
    labels: List[str] = []
    score = 0.0

    grooming_keywords = ["don't tell", "secret", "meet up alone", "send nudes", "keep this between us"]
    if any(k in text for k in grooming_keywords):
        labels.append("possible_grooming")
        score = max(score, 0.8)

    abuse_keywords = ["kill yourself", "worthless", "i will hurt you"]
    if any(k in text for k in abuse_keywords):
        labels.append("abusive_language")
        score = max(score, 0.7)

    explanation = "No significant risk detected."
    if labels:
        explanation = (
            f"Heuristic rules flagged this as potential risk ({', '.join(labels)}). "
            "This is an early model; a guardian should review."
        )

    return AnalyzeTextResponse(
        risk_score=score,
        risk_labels=labels,
        explanation=explanation,
)
    

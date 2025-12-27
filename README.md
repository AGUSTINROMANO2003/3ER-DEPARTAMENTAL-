# 3ER-DEPARTAMENTAL-PROYECTO 
/PROYECTO_GESTION_TAREAS
│
├── BACKEND_FASTAPI
│   ├── requirements.txt
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── auth.py
│   └── dependencies.py
│
└── FLUTTER_APP
    ├── pubspec.yaml
    └── lib
        └── main.dart

# =====================================================================
# ======================= BACKEND_FASTAPI ==============================
# =====================================================================

# =========================
# requirements.txt
# =========================
fastapi
uvicorn
sqlalchemy
python-jose
passlib[bcrypt]
pydantic


# =========================
# database.py
# =========================
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./tasks.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


# =========================
# models.py
# =========================
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    password = Column(String)

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    description = Column(String)
    priority = Column(String)
    status = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    due_date = Column(DateTime)
    user_id = Column(Integer, ForeignKey("users.id"))


# =========================
# schemas.py
# =========================
from pydantic import BaseModel
from datetime import datetime

class UserCreate(BaseModel):
    email: str
    password: str

class TaskBase(BaseModel):
    title: str
    description: str
    priority: str
    status: str
    due_date: datetime


# =========================
# auth.py
# =========================
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta

SECRET_KEY = "SUPER_SECRET_KEY_123"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"])

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(user_id: int):
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# =========================
# dependencies.py
# =========================
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from auth import SECRET_KEY, ALGORITHM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")


# =========================
# main.py
# =========================
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import Base, engine, SessionLocal
from models import User, Task
from schemas import UserCreate, TaskBase
from auth import hash_password, verify_password, create_token
from dependencies import get_current_user

Base.metadata.create_all(bind=engine)

app = FastAPI(title="API Gestión de Tareas")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/auth/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(400, "Usuario ya existe")
    db_user = User(
        email=user.email,
        password=hash_password(user.password)
    )
    db.add(db_user)
    db.commit()
    return {"message": "Usuario registrado"}

@app.post("/auth/login")
def login(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(401, "Credenciales incorrectas")
    return {"access_token": create_token(db_user.id)}

@app.post("/tasks")
def create_task(
    task: TaskBase,
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    new_task = Task(**task.dict(), user_id=user_id)
    db.add(new_task)
    db.commit()
    return new_task

@app.get("/tasks")
def list_tasks(
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(Task).filter(Task.user_id == user_id).all()
// =====================================================================
// =========================== FLUTTER_APP ==============================
// =====================================================================

// =========================
// pubspec.yaml
// =========================
name: task_app
version: 1.0.0

environment:
  sdk: ">=3.0.0"

dependencies:
  flutter:
    sdk: flutter
  http: ^1.2.0


// =========================
// lib/main.dart
// =========================
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

const String API_URL = "http://10.0.2.2:8000";

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      home: LoginScreen(),
    );
  }
}

class LoginScreen extends StatelessWidget {
  final emailController = TextEditingController();
  final passwordController = TextEditingController();

  Future<void> login(BuildContext context) async {
    final response = await http.post(
      Uri.parse("$API_URL/auth/login"),
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({
        "email": emailController.text,
        "password": passwordController.text,
      }),
    );

    if (response.statusCode == 200) {
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => Dashboard()),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Login")),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            TextField(
              controller: emailController,
              decoration: const InputDecoration(labelText: "Email"),
            ),
            TextField(
              controller: passwordController,
              decoration: const InputDecoration(labelText: "Password"),
              obscureText: true,
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: () => login(context),
              child: const Text("Ingresar"),
            ),
          ],
        ),
      ),
    );
  }
}

class Dashboard extends StatelessWidget {
  Future<double> getBitcoinPrice() async {
    final response = await http.get(
      Uri.parse(
        "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd",
      ),
    );
    final data = jsonDecode(response.body);
    return data["bitcoin"]["usd"].toDouble();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Dashboard")),
      body: Center(
        child: FutureBuilder<double>(
          future: getBitcoinPrice(),
          builder: (_, snapshot) {
            if (!snapshot.hasData) return const CircularProgressIndicator();
            return Text(
              "Bitcoin USD: \$${snapshot.data}",
              style: const TextStyle(fontSize: 22),
            );
          },
        ),
      ),
    );
  }
}

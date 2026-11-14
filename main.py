"""
Wude Mart API — initial backend foundation.

Run locally:
    pip install -r requirements.txt
    uvicorn main:app --reload

Before running, set a strong ADMIN_PASSWORD and a long SECRET_KEY in your
environment. This starter uses SQLite for local development. For deployment,
use HTTPS and move to managed PostgreSQL + persistent file storage.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr

APP_NAME = "Wude Mart API"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("WUDE_DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "payment_proofs"
DB_PATH = DATA_DIR / "wude_mart.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.getenv("WUDE_SECRET_KEY", "")
if len(SECRET_KEY) < 32:
    # Development convenience only. Set WUDE_SECRET_KEY explicitly in deployment.
    SECRET_KEY = secrets.token_urlsafe(48)

ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("WUDE_ACCESS_TOKEN_MINUTES", "720"))
ADMIN_EMAIL = os.getenv("WUDE_ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("WUDE_ADMIN_PASSWORD", "")
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)

app = FastAPI(
    title=APP_NAME,
    version="0.1.0",
    description="Backend API for the Wude Mart Android app and admin website.",
)

# Set WUDE_CORS_ORIGINS to comma-separated trusted admin-site origins in deployment.
cors_origins = [
    item.strip()
    for item in os.getenv("WUDE_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if item.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'customer')),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                price REAL NOT NULL CHECK(price >= 0),
                image_url TEXT NOT NULL DEFAULT '',
                available INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER NOT NULL REFERENCES users(id),
                status TEXT NOT NULL DEFAULT 'pending_payment'
                    CHECK(status IN ('pending_payment', 'payment_review', 'paid', 'processing', 'shipped', 'completed', 'cancelled')),
                total REAL NOT NULL CHECK(total >= 0),
                customer_note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS order_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
                product_id INTEGER NOT NULL REFERENCES products(id),
                product_name TEXT NOT NULL,
                unit_price REAL NOT NULL,
                quantity INTEGER NOT NULL CHECK(quantity > 0)
            );

            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL REFERENCES orders(id),
                proof_filename TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'submitted'
                    CHECK(status IN ('submitted', 'approved', 'rejected')),
                admin_note TEXT NOT NULL DEFAULT '',
                reviewed_by INTEGER REFERENCES users(id),
                created_at TEXT NOT NULL,
                reviewed_at TEXT
            );
            """
        )

        # Create the first admin only when credentials are explicitly configured.
        if ADMIN_EMAIL and ADMIN_PASSWORD:
            existing = conn.execute(
                "SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL,)
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
                    (ADMIN_EMAIL, pwd_context.hash(ADMIN_PASSWORD), now_iso()),
                )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.on_event("startup")
def startup() -> None:
    init_db()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ProductCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=5000)
    price: float = Field(ge=0)
    image_url: str = Field(default="", max_length=1000)
    available: bool = True


class ProductUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=160)
    description: Optional[str] = Field(default=None, max_length=5000)
    price: Optional[float] = Field(default=None, ge=0)
    image_url: Optional[str] = Field(default=None, max_length=1000)
    available: Optional[bool] = None


class OrderItemInput(BaseModel):
    product_id: int = Field(gt=0)
    quantity: int = Field(gt=0, le=100)


class OrderCreate(BaseModel):
    items: list[OrderItemInput] = Field(min_length=1, max_length=50)
    customer_note: str = Field(default="", max_length=1000)


class PaymentReview(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    admin_note: str = Field(default="", max_length=1000)


def create_token(user_id: int, role: str) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    return jwt.encode(
        {"sub": str(user_id), "role": role, "exp": expires},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    with db() as conn:
        user = conn.execute(
            "SELECT id, email, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return dict(user)


def admin_only(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@app.get("/")
def root():
    return {"name": APP_NAME, "version": "0.1.0", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "wude-mart-api"}


@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterRequest):
    email = str(payload.email).lower()
    with db() as conn:
        if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="Email is already registered")
        cursor = conn.execute(
            "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, 'customer', ?)",
            (email, pwd_context.hash(payload.password), now_iso()),
        )
        user_id = cursor.lastrowid
    return {"access_token": create_token(user_id, "customer"), "token_type": "bearer"}


@app.post("/api/auth/login")
def login(payload: LoginRequest):
    email = str(payload.email).lower()
    with db() as conn:
        user = conn.execute(
            "SELECT id, email, password_hash, role FROM users WHERE email = ?", (email,)
        ).fetchone()
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    return {
        "access_token": create_token(user["id"], user["role"]),
        "token_type": "bearer",
        "user": {"id": user["id"], "email": user["email"], "role": user["role"]},
    }


@app.get("/api/products")
def list_products():
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, description, price, image_url, available FROM products WHERE available = 1 ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/products/{product_id}")
def get_product(product_id: int):
    with db() as conn:
        row = conn.execute(
            "SELECT id, name, description, price, image_url, available FROM products WHERE id = ?",
            (product_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Product not found")
    return dict(row)


@app.post("/api/admin/products", status_code=201)
def create_product(payload: ProductCreate, _: dict = Depends(admin_only)):
    timestamp = now_iso()
    with db() as conn:
        cursor = conn.execute(
            """INSERT INTO products
               (name, description, price, image_url, available, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                payload.name, payload.description, payload.price, payload.image_url,
                int(payload.available), timestamp, timestamp,
            ),
        )
        product_id = cursor.lastrowid
    return {"id": product_id, "message": "Product created"}


@app.patch("/api/admin/products/{product_id}")
def update_product(product_id: int, payload: ProductUpdate, _: dict = Depends(admin_only)):
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No changes supplied")
    if "available" in updates:
        updates["available"] = int(updates["available"])
    updates["updated_at"] = now_iso()
    assignments = ", ".join(f"{key} = ?" for key in updates)
    values = list(updates.values()) + [product_id]
    with db() as conn:
        cursor = conn.execute(f"UPDATE products SET {assignments} WHERE id = ?", values)
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product updated"}


@app.delete("/api/admin/products/{product_id}")
def delete_product(product_id: int, _: dict = Depends(admin_only)):
    with db() as conn:
        cursor = conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product deleted"}


@app.post("/api/orders", status_code=201)
def create_order(payload: OrderCreate, user: dict = Depends(current_user)):
    timestamp = now_iso()
    total = 0.0
    resolved_items = []
    with db() as conn:
        for item in payload.items:
            product = conn.execute(
                "SELECT id, name, price, available FROM products WHERE id = ?",
                (item.product_id,),
            ).fetchone()
            if not product or not product["available"]:
                raise HTTPException(status_code=400, detail=f"Product {item.product_id} is unavailable")
            line_total = float(product["price"]) * item.quantity
            total += line_total
            resolved_items.append((product["id"], product["name"], product["price"], item.quantity))

        cursor = conn.execute(
            """INSERT INTO orders (customer_id, status, total, customer_note, created_at, updated_at)
               VALUES (?, 'pending_payment', ?, ?, ?, ?)""",
            (user["id"], round(total, 2), payload.customer_note, timestamp, timestamp),
        )
        order_id = cursor.lastrowid
        for product_id, name, price, quantity in resolved_items:
            conn.execute(
                """INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity)
                   VALUES (?, ?, ?, ?, ?)""",
                (order_id, product_id, name, price, quantity),
            )
    return {"order_id": order_id, "total": round(total, 2), "status": "pending_payment"}


@app.post("/api/orders/{order_id}/payment-proof", status_code=201)
async def upload_payment_proof(
    order_id: int,
    file: UploadFile = File(...),
    user: dict = Depends(current_user),
):
    if file.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=415, detail="Upload a JPG, PNG, or WebP image")
    contents = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Image must be 5 MB or smaller")
    if not contents:
        raise HTTPException(status_code=400, detail="Empty upload")

    with db() as conn:
        order = conn.execute(
            "SELECT id, status FROM orders WHERE id = ? AND customer_id = ?",
            (order_id, user["id"]),
        ).fetchone()
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        if order["status"] in ("paid", "completed", "cancelled"):
            raise HTTPException(status_code=400, detail="This order cannot accept payment proof")

        suffix = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}[file.content_type]
        filename = f"order_{order_id}_{secrets.token_hex(12)}{suffix}"
        (UPLOAD_DIR / filename).write_bytes(contents)

        conn.execute(
            """INSERT INTO payments (order_id, proof_filename, status, created_at)
               VALUES (?, ?, 'submitted', ?)""",
            (order_id, filename, now_iso()),
        )
        conn.execute(
            "UPDATE orders SET status = 'payment_review', updated_at = ? WHERE id = ?",
            (now_iso(), order_id),
        )
    # Deliberately does NOT approve payment. An admin must review it.
    return {"message": "Payment proof submitted for manual review", "status": "submitted"}


@app.get("/api/orders/mine")
def my_orders(user: dict = Depends(current_user)):
    with db() as conn:
        orders = conn.execute(
            """SELECT id, status, total, customer_note, created_at
               FROM orders WHERE customer_id = ? ORDER BY id DESC""",
            (user["id"],),
        ).fetchall()
        result = []
        for order in orders:
            items = conn.execute(
                """SELECT product_id, product_name, unit_price, quantity
                   FROM order_items WHERE order_id = ?""",
                (order["id"],),
            ).fetchall()
            result.append({**dict(order), "items": [dict(item) for item in items]})
    return result


@app.get("/api/admin/orders")
def admin_orders(_: dict = Depends(admin_only)):
    with db() as conn:
        rows = conn.execute(
            """SELECT o.id, o.customer_id, u.email AS customer_email, o.status,
                      o.total, o.customer_note, o.created_at
               FROM orders o JOIN users u ON u.id = o.customer_id
               ORDER BY o.id DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/admin/payments")
def admin_payments(_: dict = Depends(admin_only)):
    with db() as conn:
        rows = conn.execute(
            """SELECT p.id, p.order_id, p.proof_filename, p.status, p.admin_note,
                      p.created_at, o.total, u.email AS customer_email
               FROM payments p
               JOIN orders o ON o.id = p.order_id
               JOIN users u ON u.id = o.customer_id
               ORDER BY p.id DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/admin/payments/{payment_id}/review")
def review_payment(payment_id: int, payload: PaymentReview, admin: dict = Depends(admin_only)):
    timestamp = now_iso()
    with db() as conn:
        payment = conn.execute(
            "SELECT id, order_id, status FROM payments WHERE id = ?", (payment_id,)
        ).fetchone()
        if not payment:
            raise HTTPException(status_code=404, detail="Payment not found")
        if payment["status"] != "submitted":
            raise HTTPException(status_code=409, detail="Payment has already been reviewed")

        conn.execute(
            """UPDATE payments SET status = ?, admin_note = ?, reviewed_by = ?, reviewed_at = ?
               WHERE id = ?""",
            (payload.decision, payload.admin_note, admin["id"], timestamp, payment_id),
        )
        new_order_status = "paid" if payload.decision == "approved" else "pending_payment"
        conn.execute(
            "UPDATE orders SET status = ?, updated_at = ? WHERE id = ?",
            (new_order_status, timestamp, payment["order_id"]),
        )
    return {"message": f"Payment {payload.decision}", "order_status": new_order_status}


@app.patch("/api/admin/orders/{order_id}/status")
def update_order_status(
    order_id: int,
    new_status: str = Form(...),
    _: dict = Depends(admin_only),
):
    allowed = {"processing", "shipped", "completed", "cancelled"}
    if new_status not in allowed:
        raise HTTPException(status_code=400, detail="Unsupported order status")
    with db() as conn:
        cursor = conn.execute(
            "UPDATE orders SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, now_iso(), order_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Order not found")
    return {"message": "Order status updated", "status": new_status}

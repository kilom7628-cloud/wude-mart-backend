"""
Wude Mart API — High-Performance Cloudflare Python Worker with Starlette, D1 and R2.
Maintains 100% schema, route, and functional parity with FastAPI backend.
Pure-Python runtime with zero C-extension overhead for instant cold starts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

APP_NAME = "Wude Mart API"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}


# --- D1 Database Helper ---
class D1Database:
    def __init__(self, d1_binding):
        self.d1 = d1_binding

    async def execute(self, query: str, params: list = None):
        stmt = self.d1.prepare(query)
        if params:
            stmt = stmt.bind(*params)
        return await stmt.run()

    async def fetchone(self, query: str, params: list = None) -> Optional[dict]:
        stmt = self.d1.prepare(query)
        if params:
            stmt = stmt.bind(*params)
        first = await stmt.first()
        if first is None:
            return None
        if hasattr(first, "to_py"):
            return first.to_py()
        return dict(first)

    async def fetchall(self, query: str, params: list = None) -> list[dict]:
        stmt = self.d1.prepare(query)
        if params:
            stmt = stmt.bind(*params)
        res = await stmt.all()
        results = getattr(res, "results", res)
        if hasattr(results, "to_py"):
            results = results.to_py()
        return [dict(r) if not isinstance(r, dict) else r for r in results]


def get_db(request: Request) -> D1Database:
    env = request.scope.get("env")
    if not env or not hasattr(env, "DB"):
        raise HTTPException(status_code=500, detail="D1 database binding 'DB' not configured")
    return D1Database(env.DB)


def get_storage(request: Request):
    env = request.scope.get("env")
    if not env or not hasattr(env, "STORAGE"):
        raise HTTPException(status_code=500, detail="R2 storage binding 'STORAGE' not configured")
    return env.STORAGE


def get_secret_key(request: Request) -> str:
    env = request.scope.get("env")
    if env and hasattr(env, "WUDE_SECRET_KEY") and env.WUDE_SECRET_KEY:
        return str(env.WUDE_SECRET_KEY)
    return os.environ.get("WUDE_SECRET_KEY", "wude-mart-cloudflare-production-secret-2026")


# --- Password Hashing (PBKDF2-HMAC-SHA256) ---
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"pbkdf2:sha256:100000${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        parts = hashed_password.split("$")
        if len(parts) != 3:
            return False
        algo_iter, salt_b64, key_b64 = parts
        _, _, iterations = algo_iter.split(":")
        salt = base64.b64decode(salt_b64)
        expected_key = base64.b64decode(key_b64)
        derived = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(derived, expected_key)
    except Exception:
        return False


# --- Pure-Python JWT (HS256) ---
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def base64url_decode(s: str) -> bytes:
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_access_token(data: dict, secret_key: str, expires_delta_seconds: int = 86400) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = data.copy()
    payload["exp"] = int(time.time()) + expires_delta_seconds
    header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    unsigned_token = f"{base64url_encode(header_json)}.{base64url_encode(payload_json)}"
    signature = hmac.new(secret_key.encode("utf-8"), unsigned_token.encode("utf-8"), hashlib.sha256).digest()
    return f"{unsigned_token}.{base64url_encode(signature)}"


def decode_access_token(token: str, secret_key: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=401, detail="Invalid token structure")
    unsigned_token = f"{parts[0]}.{parts[1]}"
    expected_sig = hmac.new(secret_key.encode("utf-8"), unsigned_token.encode("utf-8"), hashlib.sha256).digest()
    actual_sig = base64url_decode(parts[2])
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise HTTPException(status_code=401, detail="Invalid token signature")
    payload = json.loads(base64url_decode(parts[1]).decode("utf-8"))
    if "exp" in payload and int(time.time()) > payload["exp"]:
        raise HTTPException(status_code=401, detail="Token has expired")
    return payload


async def get_current_user(request: Request) -> dict:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = auth[7:].strip()
    secret_key = get_secret_key(request)
    payload = decode_access_token(token, secret_key)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token missing subject")
    db = get_db(request)
    user = await db.fetchone("SELECT id, email, role, created_at FROM users WHERE id = ?", [int(user_id)])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_optional_user(request: Request) -> Optional[dict]:
    try:
        return await get_current_user(request)
    except Exception:
        return None


async def get_admin_user(request: Request) -> dict:
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Endpoint Handlers ---
async def root_handler(request: Request):
    return JSONResponse({"name": APP_NAME, "version": "0.2.0", "docs": "/docs", "cloud": "cloudflare-workers"})


async def health_handler(request: Request):
    return JSONResponse({"status": "ok", "service": "wude-mart-api", "runtime": "cloudflare-workers-python"})


async def register_handler(request: Request):
    body = await request.json()
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email required")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    db = get_db(request)
    existing = await db.fetchone("SELECT id FROM users WHERE email = ?", [email])
    if existing:
        raise HTTPException(status_code=409, detail="Email is already registered")

    pwd_hash = hash_password(password)
    await db.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, 'customer', ?)",
        [email, pwd_hash, now_iso()],
    )
    user = await db.fetchone("SELECT id, email, role, created_at FROM users WHERE email = ?", [email])
    token = create_access_token({"sub": str(user["id"]), "role": user["role"]}, get_secret_key(request))
    return JSONResponse({"access_token": token, "token_type": "bearer", "role": user["role"], "email": user["email"]}, status_code=201)


async def login_handler(request: Request):
    body = await request.json()
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))

    db = get_db(request)
    user = await db.fetchone("SELECT id, email, password_hash, role FROM users WHERE email = ?", [email])
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": str(user["id"]), "role": user["role"]}, get_secret_key(request))
    return JSONResponse({"access_token": token, "token_type": "bearer", "role": user["role"], "email": user["email"]})


async def me_handler(request: Request):
    user = await get_current_user(request)
    return JSONResponse({"id": user["id"], "email": user["email"], "role": user["role"], "created_at": user["created_at"]})


async def products_handler(request: Request):
    db = get_db(request)
    if request.method == "GET":
        user = await get_optional_user(request)
        if user and user.get("role") == "admin":
            products = await db.fetchall("SELECT * FROM products ORDER BY id DESC")
        else:
            products = await db.fetchall("SELECT * FROM products WHERE available = 1 ORDER BY id DESC")
        return JSONResponse(products)

    elif request.method == "POST":
        await get_admin_user(request)
        body = await request.json()
        name = str(body.get("name", "")).strip()
        if not name:
            raise HTTPException(status_code=400, detail="Product name is required")
        price = float(body.get("price", 0.0))
        description = str(body.get("description", ""))
        image_url = str(body.get("image_url", ""))
        available = int(bool(body.get("available", True)))
        now = now_iso()

        await db.execute(
            "INSERT INTO products (name, description, price, image_url, available, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [name, description, price, image_url, available, now, now],
        )
        created = await db.fetchone("SELECT * FROM products WHERE name = ? ORDER BY id DESC LIMIT 1", [name])
        return JSONResponse(created, status_code=201)


async def product_detail_handler(request: Request):
    product_id = int(request.path_params["product_id"])
    db = get_db(request)

    if request.method == "GET":
        product = await db.fetchone("SELECT * FROM products WHERE id = ?", [product_id])
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        return JSONResponse(product)

    elif request.method == "PATCH":
        await get_admin_user(request)
        product = await db.fetchone("SELECT * FROM products WHERE id = ?", [product_id])
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        body = await request.json()
        updates = []
        params = []
        for field in ["name", "description", "price", "image_url"]:
            if field in body:
                updates.append(f"{field} = ?")
                params.append(body[field])
        if "available" in body:
            updates.append("available = ?")
            params.append(int(bool(body["available"])))

        updates.append("updated_at = ?")
        params.append(now_iso())

        params.append(product_id)
        await db.execute(f"UPDATE products SET {', '.join(updates)} WHERE id = ?", params)
        updated = await db.fetchone("SELECT * FROM products WHERE id = ?", [product_id])
        return JSONResponse(updated)

    elif request.method == "DELETE":
        await get_admin_user(request)
        product = await db.fetchone("SELECT * FROM products WHERE id = ?", [product_id])
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        await db.execute("UPDATE products SET available = 0, updated_at = ? WHERE id = ?", [now_iso(), product_id])
        return JSONResponse({"message": "Product deactivated"})


async def orders_handler(request: Request):
    user = await get_current_user(request)
    db = get_db(request)

    if request.method == "GET":
        if user["role"] == "admin":
            orders = await db.fetchall(
                "SELECT o.*, u.email as customer_email FROM orders o JOIN users u ON o.customer_id = u.id ORDER BY o.id DESC"
            )
        else:
            orders = await db.fetchall("SELECT * FROM orders WHERE customer_id = ? ORDER BY id DESC", [user["id"]])

        for order in orders:
            items = await db.fetchall(
                "SELECT oi.*, p.name as product_name, p.image_url FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?",
                [order["id"]],
            )
            order["items"] = items
            payments = await db.fetchall("SELECT * FROM payments WHERE order_id = ? ORDER BY id DESC", [order["id"]])
            order["payments"] = payments
        return JSONResponse(orders)

    elif request.method == "POST":
        body = await request.json()
        items = body.get("items", [])
        if not items:
            raise HTTPException(status_code=400, detail="Order must contain at least one item")
        customer_note = str(body.get("customer_note", ""))

        total_amount = 0.0
        line_items = []
        for it in items:
            pid = int(it["product_id"])
            qty = int(it["quantity"])
            prod = await db.fetchone("SELECT * FROM products WHERE id = ? AND available = 1", [pid])
            if not prod:
                raise HTTPException(status_code=404, detail=f"Product {pid} not available")
            unit_price = float(prod["price"])
            line_total = unit_price * qty
            total_amount += line_total
            line_items.append((pid, prod["name"], qty, unit_price))

        now = now_iso()
        await db.execute(
            "INSERT INTO orders (customer_id, status, total, customer_note, created_at, updated_at) VALUES (?, 'pending_payment', ?, ?, ?, ?)",
            [user["id"], total_amount, customer_note, now, now],
        )
        order = await db.fetchone("SELECT * FROM orders WHERE customer_id = ? ORDER BY id DESC LIMIT 1", [user["id"]])
        order_id = order["id"]

        for pid, pname, qty, unit_price in line_items:
            await db.execute(
                "INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity) VALUES (?, ?, ?, ?, ?)",
                [order_id, pid, pname, unit_price, qty],
            )

        order["items"] = await db.fetchall("SELECT * FROM order_items WHERE order_id = ?", [order_id])
        return JSONResponse(order, status_code=201)


async def order_detail_handler(request: Request):
    user = await get_current_user(request)
    order_id = int(request.path_params["order_id"])
    db = get_db(request)

    order = await db.fetchone("SELECT * FROM orders WHERE id = ?", [order_id])
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if user["role"] != "admin" and order["customer_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")

    order["items"] = await db.fetchall(
        "SELECT oi.*, p.name as product_name, p.image_url FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?",
        [order_id],
    )
    order["payments"] = await db.fetchall("SELECT * FROM payments WHERE order_id = ? ORDER BY id DESC", [order_id])
    return JSONResponse(order)


async def order_status_handler(request: Request):
    await get_admin_user(request)
    order_id = int(request.path_params["order_id"])
    body = await request.json()
    new_status = body.get("status") or body.get("new_status")
    allowed = {"pending_payment", "payment_review", "paid", "processing", "shipped", "completed", "cancelled"}
    if new_status not in allowed:
        raise HTTPException(status_code=400, detail="Invalid order status")

    db = get_db(request)
    await db.execute("UPDATE orders SET status = ?, updated_at = ? WHERE id = ?", [new_status, now_iso(), order_id])
    return JSONResponse({"message": "Order status updated", "status": new_status})


async def payments_handler(request: Request):
    await get_admin_user(request)
    db = get_db(request)
    payments = await db.fetchall(
        "SELECT p.*, o.total, o.status as order_status, u.email as customer_email "
        "FROM payments p "
        "JOIN orders o ON p.order_id = o.id "
        "JOIN users u ON o.customer_id = u.id "
        "ORDER BY p.id DESC"
    )
    return JSONResponse(payments)


async def order_payment_upload(request: Request):
    user = await get_current_user(request)
    order_id = int(request.path_params["order_id"])
    db = get_db(request)

    order = await db.fetchone("SELECT * FROM orders WHERE id = ?", [order_id])
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if user["role"] != "admin" and order["customer_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")

    form = await request.form()
    proof_file = form.get("proof")

    if not proof_file or not hasattr(proof_file, "filename"):
        raise HTTPException(status_code=400, detail="Payment proof image file required ('proof')")

    content = await proof_file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File size exceeds 5MB limit")

    ext = "jpg"
    filename_lower = proof_file.filename.lower()
    if filename_lower.endswith(".png"):
        ext = "png"
    elif filename_lower.endswith(".webp"):
        ext = "webp"

    unique_filename = f"proof_{order_id}_{int(time.time())}_{secrets.token_hex(4)}.{ext}"
    storage = get_storage(request)
    try:
        from pyodide.ffi import to_js
        js_content = to_js(content)
    except Exception:
        js_content = content
    await storage.put(unique_filename, js_content)

    now = now_iso()
    await db.execute(
        "INSERT INTO payments (order_id, proof_filename, status, created_at) VALUES (?, ?, 'submitted', ?)",
        [order_id, unique_filename, now],
    )
    await db.execute("UPDATE orders SET status = 'payment_review', updated_at = ? WHERE id = ?", [now, order_id])
    payment = await db.fetchone("SELECT * FROM payments WHERE order_id = ? ORDER BY id DESC LIMIT 1", [order_id])
    return JSONResponse(payment, status_code=201)


async def payment_review_handler(request: Request):
    admin = await get_admin_user(request)
    payment_id = int(request.path_params["payment_id"])
    body = await request.json()
    decision = str(body.get("decision", "")).strip().lower()
    admin_note = str(body.get("admin_note", ""))
    if decision not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="Decision must be 'approved' or 'rejected'")

    db = get_db(request)
    payment = await db.fetchone("SELECT * FROM payments WHERE id = ?", [payment_id])
    if not payment:
        raise HTTPException(status_code=404, detail="Payment record not found")

    new_payment_status = "approved" if decision == "approved" else "rejected"
    now = now_iso()
    await db.execute(
        "UPDATE payments SET status = ?, admin_note = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?",
        [new_payment_status, admin_note, admin["id"], now, payment_id],
    )
    new_order_status = "paid" if decision == "approved" else "pending_payment"
    await db.execute("UPDATE orders SET status = ?, updated_at = ? WHERE id = ?", [new_order_status, now, payment["order_id"]])

    updated = await db.fetchone("SELECT * FROM payments WHERE id = ?", [payment_id])
    return JSONResponse(updated)


async def payment_proof_file_handler(request: Request):
    await get_admin_user(request)
    filename = request.path_params["filename"]
    storage = get_storage(request)
    obj = await storage.get(filename)
    if not obj:
        raise HTTPException(status_code=404, detail="Proof image not found")
    arr = await obj.arrayBuffer()
    if hasattr(arr, "to_py"):
        body = bytes(arr.to_py())
    else:
        body = bytes(arr)
    content_type = "image/jpeg"
    if filename.endswith(".png"):
        content_type = "image/png"
    elif filename.endswith(".webp"):
        content_type = "image/webp"
    return Response(content=body, media_type=content_type)


# --- Starlette Application Definition ---
routes = [
    Route("/", root_handler, methods=["GET"]),
    Route("/health", health_handler, methods=["GET"]),
    Route("/api/auth/register", register_handler, methods=["POST"]),
    Route("/api/auth/login", login_handler, methods=["POST"]),
    Route("/api/auth/me", me_handler, methods=["GET"]),
    Route("/api/products", products_handler, methods=["GET", "POST"]),
    Route("/api/products/{product_id:int}", product_detail_handler, methods=["GET", "PATCH", "DELETE"]),
    Route("/api/orders", orders_handler, methods=["GET", "POST"]),
    Route("/api/orders/{order_id:int}", order_detail_handler, methods=["GET"]),
    Route("/api/orders/{order_id:int}/status", order_status_handler, methods=["PATCH"]),
    Route("/api/orders/{order_id:int}/payment", order_payment_upload, methods=["POST"]),
    Route("/api/payments", payments_handler, methods=["GET"]),
    Route("/api/payments/{payment_id:int}/review", payment_review_handler, methods=["POST"]),
    Route("/api/payments/proof/{filename:str}", payment_proof_file_handler, methods=["GET"]),
]

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=[
            "https://wude-mart-admin.pages.dev",
            "https://1b692d45.wude-mart-admin.pages.dev",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "*",
        ],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )
]

app = Starlette(routes=routes, middleware=middleware)

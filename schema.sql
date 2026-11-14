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
    currency TEXT NOT NULL DEFAULT 'ETB',
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
    currency TEXT NOT NULL DEFAULT 'ETB',
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
    currency TEXT NOT NULL DEFAULT 'ETB',
    quantity INTEGER NOT NULL CHECK(quantity > 0)
);

CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL REFERENCES orders(id),
    customer_id INTEGER REFERENCES users(id),
    proof_filename TEXT NOT NULL DEFAULT '',
    payment_method TEXT NOT NULL DEFAULT 'Telebirr',
    status TEXT NOT NULL DEFAULT 'submitted'
        CHECK(status IN ('submitted', 'approved', 'rejected')),
    currency TEXT NOT NULL DEFAULT 'ETB',
    admin_note TEXT NOT NULL DEFAULT '',
    reviewed_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS payment_methods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_name TEXT NOT NULL,
    account_number TEXT NOT NULL,
    account_name TEXT NOT NULL,
    instructions TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1,
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS order_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    sender_role TEXT NOT NULL CHECK(sender_role IN ('admin', 'customer', 'system')),
    message_type TEXT NOT NULL DEFAULT 'general'
        CHECK(message_type IN ('general', 'payment_received', 'payment_approved', 'payment_rejected', 'info_requested', 'status_update')),
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);
